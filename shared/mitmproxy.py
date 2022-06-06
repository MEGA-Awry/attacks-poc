
#
# This file is part of the PoCs for various issues found in the cryptographic
# design of Mega.
#
# Content: class handling the start of the mitmproxy and querying it's state
#

from os.path import isfile
from time import sleep
from subprocess import Popen, DEVNULL

from shared.constants.mitmproxy import *

class Mitmproxy:
    def __init__(self, script_path=None, log_file=MITMPROXY_LOG_FILE):
        self.script_path = script_path
        self.log_file = log_file

        # since mitmproxy does not terminate when the script exits, we monitor
        # the log file.
        self.nr_of_prev_runs = self._get_runs()

    def _exec_fn_on_log_file(self, fn, ret_failed):
        if isfile(self.log_file):
            with open(self.log_file, "r") as log_fp:
                return fn(log_fp)
        else:
            return ret_failed

    def _get_runs(self):
        cnt_runs = lambda fp: fp.read().count(MITMPROXY_LOG_FILE_START_ID)
        return self._exec_fn_on_log_file(cnt_runs, 0)

    def is_done(self):
        def _check_log_file_if_done(fp):
            lines = fp.readlines()

            for i in reversed(range(len(lines))):
                if MITMPROXY_LOG_FILE_START_ID in lines[i]:
                    break
            return any([MITMPROXY_LOG_FILE_DONE_ID in line for line in lines[i:]])

        return self._exec_fn_on_log_file(_check_log_file_if_done, False)

    def wait(self, timeout=30):
        while timeout > 0:
            self.assure_is_alive()
            if self.is_done():
                return True
            sleep(1)
            timeout -= 1
        return False

    def get_factors(self):
        def _extract_factors(fp):
            lines = fp.readlines()

            for i in reversed(range(len(lines))):
                if MITMPROXY_LOG_FILE_DONE_ID in lines[i]:
                    break
            return lines[i+1].strip()

        return self._exec_fn_on_log_file(_extract_factors, "No factors found.")

    def assure_is_alive(self):
        proc_ret = self.proc.poll()

        if proc_ret:
            print(f"'{MITMPROXY_PATH}' stopped unexpectedly with return code {proc_ret}")
            exit(proc_ret)

    def was_restarted(self):
        if self._get_runs() > self.nr_of_prev_runs + 1:
            return True
        return False

    def start(self):
        cmd = [MITMPROXY_PATH]

        if self.script_path:
            cmd += ["-s", self.script_path]

        try:
            self.proc = Popen(cmd, stdout=DEVNULL, stderr=DEVNULL)
        except FileNotFoundError:
            print(f"Missing dependency: '{MITMPROXY_PATH}', aborting")
            exit(1)

        # Wait until the proxy is ready
        while self._get_runs() == self.nr_of_prev_runs:
            sleep(1)

    def exit(self):
        self.proc.terminate()
