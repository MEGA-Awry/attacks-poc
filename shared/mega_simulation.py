
#
# This file is part of the PoCs for various issues found in the cryptographic
# design of Mega.
#
# Content: various operations of Mega clients (both internal functions like
# padding and exposed functions like chunkwise file encryption) implemented in
# Python and allowing modifications that are useful to perform our attacks.
# Implements some API calls and responses.
#

from binascii import crc32

from Crypto.Util.number import getPrime, isPrime, inverse
from Crypto.Cipher import AES

from secrets import token_bytes, randbelow
from json import dumps, loads

from shared.attack_utils import *
from shared.constants.mega_crypto import *

def len_encode(b):
    b_bit_len = len(b) * 8
    len_enc = int_to_bytes(b_bit_len).rjust(LEN_ENCODING_BYTE_LEN, b"\x00")
    return len_enc + b

def len_decode(l):
    l_bit_len = bytes_to_int(l[:LEN_ENCODING_BYTE_LEN])
    l_end = LEN_ENCODING_BYTE_LEN + (l_bit_len // 8)
    return l[LEN_ENCODING_BYTE_LEN : l_end], l[l_end:]

def chat_len_encode(b):
    b_len = len(b)
    len_enc = int_to_bytes(b_len).rjust(LEN_ENCODING_BYTE_LEN, b"\x00")
    return len_enc + b

def chat_len_decode(l):
    l_len = bytes_to_int(l[:LEN_ENCODING_BYTE_LEN])
    return l[LEN_ENCODING_BYTE_LEN : LEN_ENCODING_BYTE_LEN + l_len]

def zero_pad(m, l):
    """
    Pad m with zeros to a multiple of l

    :param m: message
    :param l: integer for which m should be padded to be a multiple of it
    """
    m += b"\x00" * pad_len(len(m), l)
    return m

def zero_unpad(m, m_len=None):
    """
    Unpad m

    :param m: message
    :param m_len: byte length of the message m. If not given, remove all trailying
        zero bytes (non-unique padding!)
    """
    if m_len:
        return m[:m_len]
    else:
        if type(m) == str:
            pad = "\x00"
        else:
            pad = b"\x00"
        return m.rstrip(pad)

def gen_rsa_keys(modulus_size, e=RSA_PUBLIC_EXP):
    assert modulus_size % 2 == 0
    while True:
        p = getPrime(modulus_size//2)
        q = getPrime(modulus_size//2)
        n = p * q

        if n.bit_length() != modulus_size:
          continue

        phi = (p-1) * (q-1)

        try:
            d = inverse(e, phi)
        except:
            continue
        break

    u = inverse(q, p)

    assert n == p * q
    assert (u * q) % p == 1
    assert (e * d) % phi == 1

    sk = (q, p, d, u)
    pk = (n, e)

    return sk, pk

def decode_rsa_privk(sk):
    assert len(sk) == 4
    q, p, d, u = sk

    p1 = p - 1
    q1 = q - 1
    phi = p1 * q1

    dp = d % p1
    dq = d % q1

    n = p * q
    e = inverse(d, phi)

    return (n, e, d, p, q, dp, dq, u)

def decode_urlb64_rsa_pubk(pk_urlb64):
    """
    Decode urlsafe base 64 encoded public key from Mega. The format is:
    |n| || n || |e| || e
    where |b| is the bit length of b.
    """
    pk = url_decode(pk_urlb64)

    n, pk = len_decode(pk)
    n = bytes_to_int(n)

    e, _ = len_decode(pk)
    e = bytes_to_int(e)

    return n, e

def rsa_decrypt(c, sk, do_unpad=True, do_ct_len_decode=False):
    """
    Compute c^d mod n (RSA decryption)

    :param c: ciphertext in bytes
    :param sk: RSA private key, format: (n, e, d, p, q, dp, dq, u)
    :param do_unpad: do unpad the plaintext
    :param do_ct_len_encode: if True, length decode the ciphertext
    """

    if do_ct_len_decode:
        c = len_decode(c)

    c = bytes_to_int(c)
    if len(sk) > 4:
        n, e, d, p, q, dp, dq, u = sk

        # Decrypt using CRT and Garner's formula
        mp = pow(c, dp, p)
        mq = pow(c, dq, q)

        # Garner's formula for CRT
        t = (mp - mq) % p
        h = (u * t) % p
        m = (h * q + mq) % n
    elif len(sk) == 2:
        n, d = sk
        m = pow(c, d, n)
    else:
        raise ValueError(f"Decryption with {len(sk)}-component private key" \
            + "not implemented.")

    if do_unpad:
        m_pad = int_to_bytes(m).rjust(ceil_int_div(n.bit_length(), 8), b"\x00")
        if m_pad[1] != 0:
            m_pad = b"\x00" + m_pad
        m = m_pad[PREFIX_MAX_BYTE_LEN:]

    return m

def rsa_pad(m, modulus_byte_size):
    # XXX: This is just one possible server implementations, e.g., a zeri padding
    # would also be possible for some uses (but it is deterministic!)
    return b"\x00" * 2 + m + token_bytes(modulus_byte_size - 2 - len(m))

def rsa_unpad(pt_padded, modulus_byte_size):
    # left pad with zeros
    pt_padded = pt_padded.rjust(modulus_byte_size, b"\x00")
    return pt_padded[LEN_ENCODING_BYTE_LEN:]

def chat_rsa_pad(m, modulus_byte_size):
    return rsa_pad(chat_len_encode(m), modulus_byte_size)

def chat_rsa_unpad(pt_padded, modulus_byte_size):
    return chat_len_decode(rsa_unpad(pt_padded, modulus_byte_size))

def rsa_encrypt(m, pk, do_pad=True, do_ct_len_encode=False):
    """
    Compute m^e mod n (RSA encryption)

    :param m: plaintext in bytes
    :param pub: RSA public key, format: (n, e)
    :param do_pad: do pad the message before encryption
    :param do_ct_len_encode: if True, length encode the ciphertext
    :returns c: ciphertext in bytes
    """
    n, e = pk
    if do_pad:
        m_padded = rsa_pad(m, ceil_int_div(n.bit_length(), 8))
    else:
        m_padded = m
    c = pow(bytes_to_int(m_padded), e, n)

    c_bytes = int_to_bytes(c)
    if do_ct_len_encode:
        return len_encode(c_bytes)
    else:
        return c_bytes

def chat_rsa_encrypt(m, pk):
    """
    RSA encryption like rsa_encrypt but uses the chat (byte) length encoding
    """
    c = rsa_encrypt(m, pk)
    return chat_len_encode(c)

def chat_rsa_decrypt(c, sk):
    """
    RSA decryption of chat-length-encoded ciphertext
    """
    c = chat_len_decode(c)
    return rsa_decrypt(c, sk)

def aes_encrypt(m, km):
    """
    :param m: plaintext to encrypt
    :param km: Master key (16B for AES-ECB)
    """
    cipher = AES.new(km, AES.MODE_ECB)
    return cipher.encrypt(m)

def aes_decrypt(c, km):
    """
    :param c: ciphertext to decrypt
    :param km: Master key (16B for AES-ECB)
    """
    cipher = AES.new(km, AES.MODE_ECB)
    return cipher.decrypt(c)

def cbc_mac(k, m, iv=b"\x00"*AES_BLOCK_BYTE_SIZE):
    """
    Create a CBC-MAC tag for message m using key k

    :param k: key
    :param m: message, padded to AES blocks
    :param iv: initialization vector for the underlying AES-CBC scheme

    :returns: tag t
    """

    aes_cbc = AES.new(k, AES.MODE_CBC, iv=iv)
    t = aes_cbc.encrypt(m)[-AES_BLOCK_BYTE_SIZE:]

    return t

def encrypt_rsa_sk(sk, km):
    """
    Encrypt RSA private key with AES-ECB under the master key.

    :param sk: Private key of the format n, e, d, p, q, dp, dq, u
    :param km: Master key (16B for AES-ECB)
    """

    n, e, d, p, q, dp, dq, u = sk

    sk_bytes = len_encode(int_to_bytes(q))
    sk_bytes += len_encode(int_to_bytes(p))
    sk_bytes += len_encode(int_to_bytes(d))
    sk_bytes += len_encode(int_to_bytes(u))

    # padding if necessary
    sk_bytes += b"\x00" * pad_len(len(sk_bytes), AES_BLOCK_BYTE_SIZE)

    return aes_encrypt(sk_bytes, km)

def decrypt_rsa_sk(csk, km):
    """
    Decrypt RSA private key with AES-ECB and the master key.

    :params csk: encrypted secret key
    :params km: master key
    """

    sk_bytes = aes_decrypt(csk, km)

    q, sk_bytes = len_decode(sk_bytes)
    p, sk_bytes = len_decode(sk_bytes)
    d, sk_bytes = len_decode(sk_bytes)
    u, _        = len_decode(sk_bytes)

    q = bytes_to_int(q)
    p = bytes_to_int(p)
    d = bytes_to_int(d)
    u = bytes_to_int(u)

    return decode_rsa_privk((q, p, d, u))

def make_attr(attr_dict):
    """
    Create file attributes

    :param attr: dictionary with attributes, the following two fields are
        mandatory:
            - n: file name
            - c: CRC checksum

    :returns: attribute string
    """

    return f"MEGA{dumps(attr_dict)}"

def parse_attr(attr):
    """
    Parse file attributes

    :param attr: Mega attribute string

    :returns: attributes dictionary
    """

    return loads(attr[4:])

def get_metmac(mac_cond):
    """
    Compute the MetaMAC from the condensed MAC

    :param mac_cond: condensed MAC

    :returns metamac: MetaMAC
    """

    return xor_bytes(mac_cond[:4], mac_cond[4:8]) \
            + xor_bytes(mac_cond[8:12], mac_cond[12:16])

def get_file_fingerprint(fdata):
    """
    Compute the CRC32 checksum over the given data.

    :param data: File content as bytes

    :returns c: CRC32 checksum
    """

    CRC2_LEN = 16

    # TODO: not correct yet, they do a custom computation, but was not
    # necessary for PoC
    return int_to_bytes(crc32(fdata) & 0xffffffff)

def obfuscate_file_key(kF, nF, mac_cond):
    """
    Generate the obfuscated file key

    :param kF: raw file key (128 bits)
    :param nF: file nonce (64 bits)
    :param mac_cond: condensed mac (128 bits)

    :returns: the obfuscated file key (kF XOR (nF || MetaMAC)) || nF || MetaMAC
    """

    metamac = get_metmac(mac_cond)

    kF_obf_block_1 = nF + metamac
    kF_obf_block_0 = xor_bytes(kF, kF_obf_block_1)

    kF_obf = kF_obf_block_0 + kF_obf_block_1

    return kF_obf

def deobfuscate_file_key(kF_obf):
    """
    Deobfuscate the file key

    :param kF_obf: the obfuscated file key (kF XOR (nF || MetaMAC)) || nF || MetaMAC

    :returns (kF, nF, metamac): the raw file key (128 bits) kF, the file nonce
        (64 bits), and the metamac (64 bits)
    """

    kF = xor_bytes(kF_obf[:16], kF_obf[16:])
    nF = kF_obf[16:24]
    metamac = kF_obf[24:32]

    return kF, nF, metamac

def aes_ccm_encrypt(kF, m, iv):
    """
    Encrypt with Mega's custom AES-CCM implementation, which does not encrypt
    the MAC tag

    :param kF: key for both the encryption and the tag
    :param m: message to encrypt
    :param iv: Initialization Vector

    :returns: an AES-CCM ciphertext and a MAC tag
    """

    nF = iv[:8]
    i = iv[8:]

    m_padded = zero_pad(m, AES_BLOCK_BYTE_SIZE)

    # CBC-MAC over the message, with IV of nF || nF
    t = cbc_mac(kF, m_padded, iv=nF + nF)

    aes_ctr = AES.new(kF, AES.MODE_CTR, nonce=nF, initial_value=i)
    c = aes_ctr.encrypt(m_padded)

    return c, t

def aes_ccm_decrypt(kF, c, iv):
    """
    Decrypt with Mega's custom AES-CCM implementation, which does not encrypt
    the MAC tag

    :param kF: key for both the encryption and the tag
    :param c: ciphertext
    :param iv: Initialization Vector

    :returns: plaintext and its MAC tag
    """

    nF = iv[:8]
    i = iv[8:]

    aes_ctr = AES.new(kF, AES.MODE_CTR, nonce=nF, initial_value=i)
    m_padded = aes_ctr.decrypt(c)
    m = zero_unpad(m_padded)

    # CBC-MAC over the message, with IV of nF || nF
    t = cbc_mac(kF, m_padded, iv=nF + nF)

    return m, t

def encrypt_attributes(k, attr_dict, iv=b"\x00"*AES_BLOCK_BYTE_SIZE):
    """
    Encrypt attributes with AES-CBC

    :param k: key for AES-CBC
    :param attr: attribute dictionary
    :param iv: optional IV (default: zero vector)

    :returns: CBC encryption of the attributes under k
    """

    attr = make_attr(attr_dict).encode()
    attr_padded = zero_pad(attr, AES_BLOCK_BYTE_SIZE)

    aes_cbc = AES.new(k, AES.MODE_CBC, iv=iv)
    attr_enc = aes_cbc.encrypt(attr_padded)

    return attr_enc

def decrypt_attributes(k, attr_enc, iv=b"\x00"*AES_BLOCK_BYTE_SIZE):
    """
    AES-CBC decrypt attributes

    :param k: key for AES-CBC
    :param attr_enc: encrypted attributes
    :param iv: optional IV (default: zero vector)

    :returns: attribute dictionary
    """

    aes_cbc = AES.new(k, AES.MODE_CBC, iv=iv)
    attr_padded = aes_cbc.decrypt(attr_enc).decode()
    attr = zero_unpad(attr_padded)
    attr_dict = parse_attr(attr)

    if "n" not in attr_dict:
        raise Exception("Missing node name")

    return attr_dict

def chunkwise_file_encryption(kM, fname):
    """
    Split a file into chunks and encrypt them with Mega's custom AES-CCM. Then,
    compute the metamac over all chunk MACs. Furthermore, encrypt the file
    attributes with AES-CBC.

    :param kM: master key
    :param fname: name of the file to encrypt

    :returns: (cF, k_enc, attr_enc)
        where cF are is the encrypted file,
            k_enc is the encrypted obfuscated node key,
            and attr_enc are the encrypted attributes
    """

    kF = token_bytes(NODE_KEY_BYTE_LEN)
    nF = token_bytes(FILE_NONCE_BYTE_LEN)

    with open(fname, "rb") as fp:
        f = fp.read()

        #
        # Encrypt chunks
        #
        off = 0
        i = 0
        chunk_cts = []
        chunk_macs = []

        while off < len(f):
            chunk = f[off : off + FILE_CHUNK_BYTE_SIZE]

            iv = nF + i.to_bytes(8, "big")
            chunk_ct, chunk_mac = aes_ccm_encrypt(kF, chunk, iv)

            chunk_cts.append(chunk_ct)
            chunk_macs.append(chunk_mac)

            off += FILE_CHUNK_BYTE_SIZE
            i += FILE_CHUNK_BYTE_SIZE // AES_BLOCK_BYTE_SIZE

        #
        # Compute condensed MAC
        #
        mac_cond = cbc_mac(kF, b"".join(chunk_macs))

        #
        # Encrypt obfuscated file key
        #
        kF_obf = obfuscate_file_key(kF, nF, mac_cond)
        kF_enc = aes_encrypt(kF_obf, kM)

        #
        # Encrypt attributes
        #
        crc = get_file_fingerprint(f)

        attr_dict = {
            "n": fname,
            "c": url_encode(crc).decode()
        }
        attr_enc = encrypt_attributes(kF, attr_dict)

        return b"".join(chunk_cts), kF_enc, attr_enc

def chunkwise_file_decryption(kM, c, kF_enc, attr_enc):
    """
    Decrypt file chunks and reassemble the file.

    :param kM: master key
    :param c: AES-CCM encrypted file content (bytestring)
    :param kF_enc: encrypted obfuscated file key
    :param attr_enc: encrypted attributes

    :returns: content of the decrypted file and the decrypted attributes or
        throws an Exception
    """

    chunk_cts = []
    for i in range(0, len(c), FILE_CHUNK_BYTE_SIZE):
        chunk_cts.append(c[i : i + FILE_CHUNK_BYTE_SIZE])

    #
    # Get file key, nonce and metamac from obfuscated file key
    #
    kF_obf = aes_decrypt(kF_enc, kM)
    kF, nF, metamac = deobfuscate_file_key(kF_obf)

    #
    # Decrypt the file chunks
    #
    chunk_pts = []
    chunk_macs = []
    i = 0
    for chunk_ct in chunk_cts:
        iv = nF + i.to_bytes(8, "big")
        chunk_pt, chunk_mac = aes_ccm_decrypt(kF, chunk_ct, iv)

        chunk_pts.append(chunk_pt)
        chunk_macs.append(chunk_mac)

        i += FILE_CHUNK_BYTE_SIZE // AES_BLOCK_BYTE_SIZE

    #
    # Verify the MetaMAC
    #
    mac_cond = cbc_mac(kF, b"".join(chunk_macs))

    if metamac != get_metmac(mac_cond):
        raise Exception("Authentication failed: MetaMAC does not match.")

    #
    # Decrypt attributes
    #
    attr_dict = decrypt_attributes(kF, attr_enc)

    fdata = b"".join(chunk_pts)

    # Verify checksum if present
    # if "c" in attr_dict:
    #     if attr_dict["c"] != get_file_fingerprint(fdata):
    #         print(bytes_to_int(url_decode(attr_dict["c"])[:4]))
    #         print(get_file_fingerprint(fdata))
    #         raise Exception("Chunk checksum verification failed.")

    return fdata, attr_dict

def get_new_file_handle():
    """
    Generate a new file handle

    :returns: file handle string
    """
    return url_encode(token_bytes(FILE_HANDLE_BYTE_LEN)).decode()

def get_pseudo_thumbnail_attr(l=2):
    """
    Generate pseudo thumbnail attributes (just enough to make the client do a
    request for a thumbnail that we can intercept)

    :param l: Number of 'units' (whatever they do, maybe attribute 'chunks')
    """

    fa = ""
    for i in range(l-1, -1, -1):
        h = get_new_file_handle()
        fa += f"{randbelow(1000)}:{i}*{h}/"

    return fa[:-1]

def api_find_root_node(j):
    """
    :param j: JSON response of a fetch nodes command.

    :returns: root node or None if not found
    """

    for file_json in j:
        if file_json["t"] == 2: # type 2 is the root node
            return file_json

    return None

def api_find_root_node_handle(j):
    """
    :param j: JSON response of a fetch nodes command.

    :returns: root node handle or None if not found
    """

    root_node = api_find_root_node(j)
    if root_node:
        return root_node["h"]
    return None

def api_find_owner_handle(j):
    """
    :param j: JSON response of a fetch nodes command.

    :returns: owner user handle of the root node (i.e., this cloud)
    """

    root_node = api_find_root_node(j)
    if root_node:
        return root_node["u"]
    return None

def api_find_obf_key_enc(j, handle):
    """
    :param j: JSON response of a fetch nodes command.
    :param h: handle of target file.

    :returns: obfuscated key encryption or None if not found
    """

    for file_json in j:
        if file_json["h"] == handle:
          return url_decode(file_json["k"].split(":")[-1])

    return None


def api_create_file_node(file_handle, parent_handle, owner_handle, attr,
    file_key, file_size, file_attributes=None):
    """
    :param file_handle: file's handle (ID)
    :param parent_handle: handle of the file's parent node
    :param owner_handle: user handle of the file's owner
    :param attr: (encrypted) file attributes
    :param file_key: file key (obfuscated)
    :param file_size: size of the file
    :param file_attributes: additional file attributes (e.g. thumbnail handles)
    """

    file_json = {
        "h": file_handle,
        "p": parent_handle,
        "t": 0, # type: FILENODE
        "a": url_encode(attr).decode(),
        "k": owner_handle + ":" + url_encode(file_key).decode(),
        "s": file_size,
    }

    if file_attributes:
        file_json["fa"] = file_attributes

    return file_json

def api_file_attr_fetch_response(storage_server, node):
    """
    Generate the JSON response for a file request

    :param storage_server: tuple containing the storage server's URL and IPv4/6
      addresses.
    :param node: file node for which the data should be fetched
    """

    url, ipv4, ipv6 = storage_server

    d = {
        "g": url,
        "ip": [ipv4, ipv6],
        "s": node["s"],
        "at": node["a"],
        "msd": 1, # No MegaSync Download
        "tl": 0,
        "pfa": 1 # always allow user to write attributes
    }

    if "fa" in node:
        d["fa"] = node["fa"]

    return d
