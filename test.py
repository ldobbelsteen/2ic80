import hashlib


def main(possibleValues, hashValue):
    for a in possibleValues:
        for b in possibleValues:
            for realm in possibleValues:
                for random in possibleValues:
                    generatedHash = generateHash(a, b, realm, random)
                    print(generatedHash)
                    if hashValue == generatedHash:
                        print("Found it:")
                        print("a: " + a)
                        print("b: " + b)
                        print("realm: " + realm)
                        print("random: " + random)
                        return


def main2(possibleValues, hashValue):
    for username in possibleValues:
        for password in possibleValues:
            for h in possibleValues:
                for j in possibleValues:
                    generatedHash = generateHash2(username, password, h, j)
                    print(generatedHash)
                    if hashValue in generatedHash:
                        print("Found it:")
                        print("username: " + username)
                        print("password: " + password)
                        print("h: " + h)
                        print("j: " + j)
                        return


def generateHash(username, password, realm, random):
    ha1_str = username + ":" + realm + ":" + password
    ha1 = hashlib.md5(ha1_str.encode())

    response_str = username + ":" + random + ":" + ha1.hexdigest()
    response = hashlib.md5(response_str.encode())

    return response.hexdigest()


def generateHash2(username, password, h, j):
    ha1_str = username + ":" + h + ":" + password
    c = hashlib.md5(ha1_str.encode())

    response_str = username + ":" + h + ":" + j
    e = hashlib.md5(response_str.encode())

    return c.hexdigest(), e.hexdigest(), hashlib.md5(
            (c.hexdigest() + ":" + e.hexdigest()).encode()).hexdigest(), hashlib.md5(
            (e.hexdigest() + ":" + c.hexdigest()).encode()).hexdigest()


def listValues():
    return "a", "b", "cyan"


if __name__ == '__main__':
    # values = ["admin", "SecretPassword", "global.login", "Web3.0", "Direct", "Default", "3",
    #           "be7dcfc7d3fb33e74f028ce4498b60de", "Login to 4H01D66PAJ2FA64", "71596D591679A707721AD797437DE105",
    #           "4H01D66PAJ2FA64", "common/common", "/RPC2_Login", "WatchNet", "common", "0", "DH-SD22204T-GN",
    #           "192.168.1.108", "610802327", "38AF29BBBCAB", "1734448651", "74c849e83cee1cb0f52b3457eb2bbc83",
    #           "80668fc41b6204dfac1597f0b2bbe681a7acd337", "268632079"]
    # hashVal = "2252F542A0C5131CA849BC031B0C876C"
    # main2(values, hashVal)
    # print(generateHash("SecretPassword", "admin", "Login to 4H01D66PAJ2FA64", "38AF29BBBCAB"))
    a = "admin"
    b = "SecretPassword"
    j = {"random": "547374329", "realm": "Login to 4H01D66PAJ2FA64"}
    random = "547374329"

    ha1_str = a + ":" + j.get("realm") + ":" + b
    ha1 = hashlib.md5(ha1_str.encode())

    print(ha1.hexdigest())
    response_str = a + ":" + random + ":" + ha1.hexdigest().upper()
    response = hashlib.md5(response_str.encode())
    print(response.hexdigest())
    print(hashlib.md5("hoi".encode()).hexdigest())
