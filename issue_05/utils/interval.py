
#
# This file is part of the PoCs for various issues found in the cryptographic
# design of Mega.
#
# Content: Implementation of intervals used in the smanager to try already
# queried multipliers.
#

class Interval:
    """
    Interval [a, b]
    """

    def __init__(self, a, b):
        self.a = a
        self.b = b

    def __contains__(self, item):
        return self.a <= item <= self.b

    def __str__(self):
        return f"[{hex(self.a)}, {hex(self.b)}]"

    def __repr__(self):
        return self.__str__()

    def __eq__(self, other):
        return isinstance(other, Interval) and self.a == other.a and self.b == other.b

def intersect_interval_lists(intervals_1, intervals_2):
    intervals_1 = sorted(intervals_1, key=lambda x: x.a)
    intervals_2 = sorted(intervals_2, key=lambda x: x.a)

    intervals = []
    idx_1 = 0
    idx_2 = 0

    while idx_1 < len(intervals_1) and idx_2 < len(intervals_2):
        if intervals_1[idx_1].b >= intervals_2[idx_2].a:
            while True:
                max_a = max(intervals_1[idx_1].a, intervals_2[idx_2].a)
                min_b = min(intervals_1[idx_1].b, intervals_2[idx_2].b)

                if max_a <= min_b:
                    intervals.append(Interval(max_a, min_b))

                if intervals_2[idx_2].a > intervals_1[idx_1].b or idx_2 == len(intervals_2) - 1:
                    break

                idx_2 += 1
        idx_1 += 1

    return intervals

def run_interval_sanity_checks(print_prefix):
    print(f"{print_prefix}Run sanity checks for Interval")

    # Empty right
    intervals_1 = [Interval(0, 5)]
    intervals_2 = []
    intervals_res = []
    assert intersect_interval_lists(intervals_1, intervals_2) == intervals_res
    print(f"#{print_prefix}Intersect empty intervals: success")

    # Empty left
    intervals_1 = []
    intervals_2 = [Interval(0, 5)]
    intervals_res = []
    assert intersect_interval_lists(intervals_1, intervals_2) == intervals_res
    print(f"#{print_prefix}Intersect with left empty interval: success")

    # Contained
    intervals_1 = [Interval(2, 3)]
    intervals_2 = [Interval(0, 5)]
    intervals_res = [Interval(2, 3)]
    assert intersect_interval_lists(intervals_1, intervals_2) == intervals_res
    print(f"#{print_prefix}Intersect contained intervals: success")

    # Intersection left
    intervals_1 = [Interval(0, 3)]
    intervals_2 = [Interval(2, 5)]
    intervals_res = [Interval(2, 3)]
    assert intersect_interval_lists(intervals_1, intervals_2) == intervals_res
    print(f"#{print_prefix}Intersect left-extending intervals: success")

    # Intersection right
    intervals_1 = [Interval(2, 7)]
    intervals_2 = [Interval(0, 5)]
    intervals_res = [Interval(2, 5)]
    assert intersect_interval_lists(intervals_1, intervals_2) == intervals_res
    print(f"#{print_prefix}Intersect right-extending intervals: success")

    # Multiple
    intervals_1 = [Interval(2, 7), Interval(13, 15), Interval(20,23)]
    intervals_2 = [Interval(0, 5), Interval(11, 22)]
    intervals_res = [Interval(2, 5), Interval(13,15), Interval(20,22)]
    assert intersect_interval_lists(intervals_1, intervals_2) == intervals_res

    intervals_1 = [Interval(0, 5), Interval(11, 22)]
    intervals_2 = [Interval(2, 7), Interval(13, 15), Interval(20,23)]
    intervals_res = [Interval(2, 5), Interval(13,15), Interval(20,22)]
    assert intersect_interval_lists(intervals_1, intervals_2) == intervals_res

    print(f"#{print_prefix}Intersect multiple intervals: success")
