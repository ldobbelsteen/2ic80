import hashlib


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


# Example authorization header from an 'OPTIONS' RTSP request with password 'SecretPassword':
# Authorization: Digest username="admin", realm="Login to 4H01D66PAJ2FA64", nonce="ca3a440596cc3a91f9e325547e3a208e", uri="rtsp://192.168.1.108:554", response="41ebde6e61f0fc2aa0bd0b157c4465de"
# digest_hash("admin", "Login to 4H01D66PAJ2FA64", "SecretPassword", "OPTIONS", "rtsp://192.168.1.108:554", "ca3a440596cc3a91f9e325547e3a208e") == 41ebde6e61f0fc2aa0bd0b157c4465de

generate_target("admin", "Login to 4H01D66PAJ2FA64", "OPTIONS", "rtsp://192.168.1.108:554",
                "ca3a440596cc3a91f9e325547e3a208e", "41ebde6e61f0fc2aa0bd0b157c4465de")

# hashcat -m 11400 -a 0 target.txt dictionary.txt --potfile-disable -o cracked.txt
# https://www.reddit.com/r/HowToHack/comments/p5jg9t/question_about_using_hashcat_to_crack_http_digest/
# https://hashcat.net/wiki/doku.php?id=example_hashes
# https://github.com/hashcat/hashcat/issues/1021
# https://hashcat.net/forum/archive/index.php?thread-6571.html
# https://github.com/hashcat/hashcat/blob/master/src/modules/module_11400.c
# https://hashcat.net/forum/printthread.php?tid=6768
