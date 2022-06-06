import hashlib

# CRACKING A RTSP SESSION
#
# Get the 'Authorization' header of a RTSP packet like the ones at the bottom of this script.
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

# SETUP Authorization: Digest username="admin", realm="Login to 4H01D66PAJ2FA64", nonce="cf2b0424d061a766894102f06ec0b0a7", uri="rtsp://192.168.1.108:554/", response="a77a5ac69d67e65c91c3bbb796e629a3"


generate_target("admin", "Login to 4H01D66PAJ2FA64", "SETUP", "rtsp://192.168.1.108:554/",
                "cf2b0424d061a766894102f06ec0b0a7", "a77a5ac69d67e65c91c3bbb796e629a3")
