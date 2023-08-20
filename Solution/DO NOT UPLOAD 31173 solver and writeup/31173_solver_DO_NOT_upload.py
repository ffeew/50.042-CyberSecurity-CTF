import json
import random
import socket
import time

from Crypto.Util.number import long_to_bytes

HOSTNAME = "localhost"
PORT = 31173
CIPHERTEXT_REQUEST = '{"service": "ciphertext"}'
PUBLIC_REQUEST = '{"service": "public"}'
ROUNDS = 0
CONNECTIONS = 999
DELAY = 0.2
OUT = "flag.txt"
FLAG = b"fcs22{bru73_f0rc31ng_cc42_f0r_cr4m3r_5h0up_l173_15_fun}"


def harden(q, repeat=1):
    if repeat == 0:
        return q
    else:
        return harden((q - 1) // 2, repeat - 1)


def bruteforce(hostname, port, cipher_req, public_req, rounds, connections, delay=0.0):
    """Repeat attack with random m_prime and k_prime, guaranteeing collision when large enough"""
    success = 0
    tries = 0
    failures = 0
    start = time.time()
    with open(OUT, "wb") as out:
        for connection in range(connections + 1):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((hostname, port))
            data = s.recv(4096)
            for i in range(rounds + 1):
                try:
                    s.sendall(cipher_req.encode())
                except BrokenPipeError:
                    return -1
                data = s.recv(4096)
                ciphertext = json.loads(data.strip())
                u = ciphertext["u"]
                u2 = ciphertext["u2"]
                e = ciphertext["e"]
                v = ciphertext["v"]
                time.sleep(delay)
                try:
                    s.sendall(public_req.encode())
                except BrokenPipeError:
                    return -1
                data = s.recv(4096)
                public = json.loads(data.strip())
                p = public["p"]
                g = public["g"]
                g2 = public["g2"]
                h = public["h"]

                # We choose k_prime specifically to match the magnitude that we expect to pass the bruteforce in 1000
                # attempts at most
                q = harden(p, 6)
                m_prime = random.randrange(2, p - 1)
                k_prime = random.randrange(p - q, p - 1)
                e_prime = (e * pow(h, k_prime, p) * m_prime) % p
                u_prime = (u * pow(g, k_prime, p)) % p
                u2_prime = (u2 * pow(g2, k_prime, p)) % p
                v_prime = u2_prime
                decrypt_req = '{"service": "decryption", "p":"' + str(p) + '", "u":"' + str(u_prime) + '", "u2":"' + str(u2_prime) + '", "e":"' + str(e_prime) + '", "v":"' + str(v_prime) + '"}'
                time.sleep(delay)
                try:
                    s.sendall(decrypt_req.encode())
                except BrokenPipeError:
                    return -1
                data = s.recv(4096)
                flag_received = json.loads(data.strip())
                m_p_prime = flag_received["result"]
                flag = long_to_bytes((m_p_prime * pow(m_prime, -1, p)) % p)
                if flag == FLAG:
                    success += 1
                    out.write(flag)
                    out.write("\n".encode("utf-8"))
                    print(flag)
                    print(f"Broken in {time.time() - start}s on try {tries}!")
                tries += 1
                if tries % 100 == 0:
                    print(f"Tries: {tries}")
            # print("Connection closed.")
            s.close()
    failures = tries - success
    # Since the probability of bruteforcing through the size condition check is a matter of luck, the script guarantees
    # 1000 attempts at an interval of 0.6 seconds per attempt, for a total running time of at most 10 minutes
    # Failure rate in testing over multiple instances does not exceed 99.8%, hence the challenge is solvable in the constraints given
    print(f"Total successes: {success} out of {tries}\n"
          f"Total failures: {failures} out of {tries}\n"
          f"Failure rate: {(failures / tries) * 100}%")


def naive_attack(hostname, port, cipher_req, public_req, delay):
    """Attempt CCA attack on the poorly implemented CS-lite cryptosystem,
    using chosen ciphertext of 1,
    naively fails due to check in decryption"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((hostname, port))
    data = s.recv(4096)
    try:
        s.sendall(cipher_req.encode())
    except BrokenPipeError:
        return -1
    data = s.recv(4096)
    ciphertext = json.loads(data.strip())
    u = ciphertext["u"]
    u2 = ciphertext["u2"]
    e = ciphertext["e"]
    v = ciphertext["v"]
    time.sleep(delay)
    try:
        s.sendall(public_req.encode())
    except BrokenPipeError:
        return -1
    data = s.recv(4096)
    public = json.loads(data.strip())
    p = public["p"]
    g = public["g"]
    h = public["h"]
    m = 1
    k = random.randrange(1, p - 1)
    if k % 2 == 0:
        k += 1

    # We choose u2 and v to be equal naively, disregarding the bruteforce component that has replaced the secure check
    u_prime = (u * pow(g, k, p)) % p
    u2 = 1
    e_prime = (e * (pow(h, k, p) * m) % p) % p
    v = 1
    decrypt_req = '{"service": "decryption", "p":"' + str(p) + '", "u":"' + str(u_prime) + '", "u2":"' + str(
        u2) + '", "e":"' + str(e_prime) + '", "v":"' + str(v) + '"}'
    time.sleep(delay)
    try:
        s.sendall(decrypt_req.encode())
    except BrokenPipeError:
        return -1
    data = s.recv(4096)
    flag_received = json.loads(data.strip())
    decrypted = flag_received["result"]
    if decrypted > 0:
        flag = long_to_bytes(decrypted)
        print(flag)
    else:
        print("Attack failed")


def main():
    naive_attack(HOSTNAME, PORT, CIPHERTEXT_REQUEST, PUBLIC_REQUEST, DELAY)
    bruteforce(HOSTNAME, PORT, CIPHERTEXT_REQUEST, PUBLIC_REQUEST, ROUNDS, CONNECTIONS, DELAY)


if __name__ == "__main__":
    main()
