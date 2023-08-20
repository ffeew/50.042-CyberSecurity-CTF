import time
import random
from Crypto.Util.number import *
from Crypto.Hash import SHA3_256
import sys

# change path for utils/listener
sys.path.insert(0, '/home/dinhtta/istd50042_ctf/utils')
import listener


FLAG = b"fcs22{????????????????????????????????????????????????}"
HIDDEN = 0


def harden(q, repeat=1):
    if repeat == 0:
        return q
    else:
        return harden((q - 1) // 2, repeat - 1)


def genkey(k):
    p = getStrongPrime(k)
    q = (p - 1) // 2
    both_found = False
    while not both_found:
        g = getRandomRange(3, p)
        g2 = getRandomRange(3, p)
        safe = 1
        if pow(g, 2, p) == 1 or pow(g2, 2, p) == 1:
            safe = 0
        if safe and pow(g, q, p) == 1:
            safe = 0
        elif safe and pow(g2, q, p) == 1:
            safe = 0
        if safe and divmod(p - 1, g)[1] == 0:
            safe = 0
        elif safe and divmod(p - 1, g2)[1] == 0:
            safe = 0
        g_inv = inverse(g, p)
        g2_inv = inverse(g2, p)
        if safe and divmod(p - 1, g_inv)[1] == 0:
            safe = 0
        elif safe and divmod(p - 1, g2_inv)[1] == 0:
            safe = 0
        if safe:
            both_found = True
    q2 = harden(q, 6)
    x = random.randrange(p - q2, p - 1)
    if x % 2 == 0:
        x += 1
    x2 = random.randrange(2, p - 1)
    if x2 % 2 == 0:
        x2 += 1
    y = random.randrange(2, p - 1)
    if y % 2 == 0:
        y += 1
    y2 = random.randrange(2, p - 1)
    if y2 % 2 == 0:
        y2 += 1
    z = random.randrange(2, p - 1)
    if z % 2 == 0:
        z += 1
    c = (pow(g, x, p) * pow(g2, x2, p)) % p
    d = (pow(g, y, p) * pow(g2, y2, p)) % p
    h = pow(g, z, p)
    return p, g, g2, c, d, h, x, x2, y, y2, z


def encrypt(p, g, g2, c, d, h, m):
    k = random.randrange(2, p - 1)
    if k % 2 == 0:
        k += 1
    u = pow(g, k, p)
    u2 = pow(g2, k, p)
    e = (pow(h, k, p) * m) % p
    a = (u * u2 * e) % p
    a = SHA3_256.new(str(a).encode("utf-8"))
    a = bytes_to_long(a.digest())
    v = (pow(c, k, p) * pow(d, (k * a), p)) % p
    return u, u2, e, v


def decrypt(p, x, x2, y, y2, z, u, u2, e, v):
    a = (u * u2 * e) % p
    a = SHA3_256.new(str(a).encode("utf-8"))
    a = bytes_to_long(a.digest())
    s = pow(u, x, p)
    s2 = pow(u2, x2, p)
    t = pow(u, y, p)
    t2 = pow(u2, y2, p)
    w = pow((t * t2), a, p)
    w2 = (s * s2 * w) % p
    if u2 == v:
        q = pow(u, z, p)
        q1 = inverse(q, p)
        if w2 > x:
            m = (e * q1) % p
            return m
        else:
            return -1


def refresh_globals():
    p, g, g2, c, d, h, x, x2, y, y2, z = genkey(1024 + 256)
    m = bytes_to_long(FLAG)
    u, u2, e, v = encrypt(p, g, g2, c, d, h, m)
    return p, g, g2, c, d, h, x, x2, y, y2, z, u, u2, e, v


P, G, G2, C, D, H, X, X2, Y, Y2, Z = genkey(1024 + 256)
M = bytes_to_long(FLAG)
U, U2, E, V = encrypt(P, G, G2, C, D, H, M)
TIMEOUT = HIDDEN
RETRIES = HIDDEN
DETER = HIDDEN


class Challenge:
    def __init__(self):
        self.before_input = "dbZwmwdbpqwbZmqZdqwZwdmpwqpqwZpppmbdpdbpqbpdZZZZpbpwpqZZZbZbbwwd\n" \
                            "mkkbbkmdppwmwqmqdpmqdqqbbqpqqdwkbkqdqpbkmdpqpkmdkqmbbpddmpwwddmw\n" \
                            "wqwmq____wmqwm_____qwmpwxq__wqpmwmw_____mwqp_wmpqmmwpp______mwqm\n" \
                            "dhdb/ __ \\hkd|  __ \\bdkhd/  \\dbkhd/ ____|kb| |    dkb|  ____|hkb\n" \
                            "hdk| |  | |db| |__| /kdh/ /\\ \\dkh| |    dhb| |    kbd| |____bdkh\n" \
                            "kkh| |  | |bh|  _  /dhb| |__| |bh| |    khb| |    dkb|  ____|kdb\n" \
                            "*oa| |__| |ao| |$\\ \\ao*|  __  |*#| |____ o#| |____o*#| |____##oa\n" \
                            "a#a*\\____/ao*|_|#o\\_\\oo|_/a*\\_|*o#\\_____|#*|______|a#|______|#o*\n" \
                            "#aao*#$$$$#ao#*$oa##$o*#a$oa##$ao#a#$$$$$*#o#$$$$$$o*#*$$$$$$ao#\n" \
                            "oa#o*a#o*MaW*a*oW*#Wo*#aM____M*aao______W#Mo*WaW#*aWo#oo#MWa*#AM\n" \
                            "&W&W*#WWW#aoaoMaW#&M#o**/ __ \\MW*|  ____|*#&*oWWWo#o#WM##*MWMMa&\n" \
                            "MMW&##*aM#aWaMWaWao#o&*| |  | |#&| |____oo**ao*aoWM*#*Wa&&M*M*W*\n" \
                            "oaM*WooaMoa##a*#M&a##a&| |  | |Ma|  ____|&W**#M#aaMoaMMMMoaW&#&M\n" \
                            "M&aoWMW&*M*M&M*MM#*##a*| |__| |oa| |W#a&&###oo#a*W##*a*WM&a#ao*a\n" \
                            "WMWWo&#Woa#oMo*aa#Ma*#a#\\____/W&&|_|W&WW*o&WWWWa#aW#WWa#MW#&aa&*\n" \
                            "8*888#*8W#&#*%#&#M*M#%#*MM$$$$M#M%&$*8&M8**%W*M&*&#8M&%W*&88&8**\n" \
                            "*W**88M8&8&8W#8#&#8_____M8%##_____8%W%*_____#&#&#8%&&#WW*MW8%M%8\n" \
                            "MW8##8MWW8%W&M#WWW/ ____|MW#/ ____|##&/ ____|8W&&%#%8&8%%W%#%8%#\n" \
                            "8&#&%&%&W8&%8##MW| |    #88| |___#%&8| |___%W&8W#%MWM#W8&8WW%W%#\n" \
                            "#B%W###%MB%BBMMBW| |    88MM\\___ \\M8&&\\___ \\%BWMWBM&#8#&M8M%WW#B\n" \
                            "&&8M&&MMM8W#M%B%8| |____&%B&____| |MBB____| |MB88MWW8M8%B%MWB&&W\n" \
                            "M8M%8W%%MM%WM88%%B\\_____|%&|_____/%&&|_____/&8%&%%WW%&%%8&W%WW%M\n" \
                            "%W%@8W8MW&B&BB%&W8WW$$$$$%M@@$$$$$8@@W8$$$$$8&@MW8MW8%B@BM88M@8%\n" \
                            "MMWB$B8@@W$$M%M$8M$%M@M%WMM8B%%BBM$B8MW$@@%%@B$$MBMM%%$@M8W$W%%8\n\n" \
                            "Welcome to the Oracle of Campbell Soup Security Pte. Ltd., \n" \
                            "unfortunately we are undergoing maintenance, \nand only have a few services available.\n" \
                            "Please follow the instructions below to access our services.\n\n" \
                            "For decryption, provide \n{'service': 'decryption', 'p': '<your_value>', 'u': '<your_value>', 'u2': '<your_value>', 'e': '<your_value>', 'v': '<your_value>'}\n\n" \
                            "Else, to view the encrypted flag, provide \n{'service': 'ciphertext'}\n\n" \
                            "Alas our public key seems to be broken, to view the broken public key, provide \n{'service': 'public'}\n\n" \
                            "Enter values here:\n"
        self.P = P
        self.G = G
        self.G2 = G2
        self.C = C
        self.D = D
        self.H = H
        self.X = X
        self.X2 = X2
        self.Y = Y
        self.Y2 = Y2
        self.Z = Z
        self.U = U
        self.U2 = U2
        self.E = E
        self.V = V
        self.refresh = False
        self.retries = 0
        self.deter = 0
        self.timeout_secs = TIMEOUT

    def challenge(self, message):
        if self.refresh:
            self.P, self.G, self.G2, self.C, self.D, self.H, self.X, self.X2, self.Y, self.Y2, self.Z, self.U, self.U2, self.E, self.V = refresh_globals()
            self.refresh = False
            return {"alert": "Sorry for the wait, server underwent fault checks, please retry previous command"}
        if not "service" in message:
            self.exit = True
            return {"error": "Please request a service"}
        if self.retries < RETRIES and time.time() - self.deter > DETER:
            self.deter = time.time()
            self.retries += 1
            service = message["service"]
            if service == "decryption":
                p = int(message["p"])
                u = int(message["u"])
                u2 = int(message["u2"])
                e = int(message["e"])
                v = int(message["v"])
                if u == self.U or u2 == self.U2 or e == self.E or v == self.V:
                    return {"error": "Super secret patented Campbell Soup Security recipe's ciphertext detected, we will not decrypt this for you :p"}
                else:
                    out = decrypt(p, self.X, self.X2, self.Y, self.Y2, self.Z, u, u2, e, v)
                    if out < 0:
                        self.refresh = True
                    return {"result": out}
            elif service == "ciphertext":
                return {"u": self.U, "u2": self.U2, "e": self.E, "v": self.V}
            elif service == "public":
                return {"p": self.P, "g": self.G, "g2": self.G2, "h": self.H}
            else:
                self.exit = True
                return {"error": "Please enter a valid service"}
        else:
            self.exit = True
            msg = "Something went wrong, please try again"
            if self.retries >= RETRIES:
                msg = "Max retries reached, please come again soon"
            elif time.time() - self.deter <= DETER:
                msg = "Bruteforce detected"
            return {"error": msg}


import builtins
builtins.Challenge = Challenge
"""
When you connect, the 'challenge' function will be called on your JSON
input.
"""
listener.start_server(port=HIDDEN)
