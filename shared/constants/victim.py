
#
# This file is part of the PoCs for various issues found in the cryptographic
# design of Mega.
#
# Content: parameters for a victim Mega account. This is private key information
# and compromises any security guarantees of that account. The account was
# created solely for the purpose of this PoC and contains no confidential data.
#

# TODO: Enter the email account of the target user
VICTIM_UNAME = ""

# TODO: Enter the RSA public key of the target user
VICTIM_PUBK_URL_B64 = ""

# TODO: Enter your master key. This is equal to the recovery key that you
# can export in the GUI.
VICTIM_KM_URL_B64 = ""

# TODO: Add private key information of your test account. See README for 
# suggestions on how to extract this for your account.
#
# Attention! The order of Q and P matters. Our attack assumes that
# U = Q^-1 mod P
# This does not necessarily correspond to the names used internally by your
# MEGA client, i.e., it is possible that it uses U = P^-1 mod Q and you 
# therefore need to set VICTIM_RSA_Q to the value of P.
VICTIM_RSA_Q = None
VICTIM_RSA_P = None
VICTIM_RSA_D = None
VICTIM_RSA_U = None

# Number of seconds to sleep as precaution to not spam too many login requests. 
MIN_TIME_BETWEEN_LOGINS = 1

# The name of the file that is forged and added to the cloud storage.
FORGE_FILE_NAME = "res/hacker-cat.png"

# Prepare a file with the name "file.data". One PoC shares this file.
SHARE_FILE_NAME = "file.data"

# This handle changes when you change the account. The real cloud provider
# knows this mapping from share handle to file handle.
SHARE_FILE_HANDLE = "" # TODO: add handle of the shared file (see README)
