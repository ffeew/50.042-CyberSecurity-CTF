import base64
import os
import sys
from Crypto.Hash import SHA1

# CHANGE THIS: path to your directory
sys.path.insert(0, r'/home/dinhtta/istd50042_ctf/utils')
import listener

# use the true flag when the code is running on the server
# use the fake flag when publishing the code

FLAG = "fcs22{xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx}"

secret_key = b'xxxxxxxxxxxxxxxx'
original_message = "VDU="
MAC = "fb92d54b2136c756ee80b2d2d8fd925ceccd09f4"

new_message = 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
new_MAC = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

def check(message, MAC, secret_key):
    h = SHA1.new()
    h.update(secret_key + message)
    return h.hexdigest() == MAC


class Challenge():
    def __init__(self):
        self.before_input = f"Welcome to Scam the Server\n\nThis challenge is the precursor to our main challenge, its flag will be the port number of our main challenge.\n\nIn this challenge, you will be given a message and a MAC. You will need to scam the server into returning you a flag by sending to it a message that contains a magic word.\n\nThe server checks if the MAC matches with the message as well so simply modifying the message to the server will not work :p\n\nThe original message is {original_message}\nThe original MAC is {MAC}.\n\nMAC is generated by: MAC = SHA1(secret_key||message)\n\nThe server expects inputs to be in this format: " + "{\"message\": message, \"MAC\": mac}\n\nHints:\n\
        1. The message is encoded in base64\n\
        2. appending \"flag\" to the message will signal the server to return the flag\n\
        3. secret_key length = 16\n\n"

    def challenge(self, your_input):

        if "message" in your_input and "MAC" in your_input:
            message_bytes = your_input["message"].encode()
            decoded_message = base64.b64decode(message_bytes)
            try:
                message_matches_MAC = check(decoded_message, your_input["MAC"], secret_key)
                if message_matches_MAC:
                    answer = {
                        "message": new_message,
                        "MAC": new_MAC
                        }
                    if your_input == answer:
                        return {"flag": FLAG}
                    else:
                        if your_input["message"]!=new_message and your_input["MAC"]!=new_MAC:
                            return {"error": "Wrong message and MAC"}

                        elif your_input["message"]!=new_message:
                            return {"error": "Wrong message"}

                        else:
                            return {"error": "Wrong MAC"}
                else:
                    return {"error": "The MAC does not match the message"}
            except:
                return {"error": "Please check your inputs, the server does not recognize them"}
        else:
            self.exit = True
            return {"error": "Please ensure that the data is in this format: {\"message\": message, \"MAC\": mac}"}


import builtins
builtins.Challenge = Challenge
"""
When you connect, the 'challenge' function will be called on your JSON
input.
"""
listener.start_server(port=12065)