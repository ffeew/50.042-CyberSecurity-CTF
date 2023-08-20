from Crypto.Hash import SHA1
import base64
import secrets
import sys
import os
import hlextend.hlextend as hlextend


# mac generation
# takes in a decoded binary string
def mac(msg):
    # generate a 16 byte key using secrets
    key = secrets.token_bytes(16)
    h = SHA1.new()
    # mac = SHA1(key || msg)
    h.update(key + msg)
    return h.hexdigest(), key

# print(mac(b"T5"))

# Attack
"""
This length extension attack implementation uses the hlextend module
source: https://github.com/stephenbradshaw/hlextend
"""
# secret_key generated using mac()
# hardcding the value of secret key to ensure deterministic results
# secret_key is just for checking if the attack is correct, the attack does not actually use the value of the secret key
secret_key = b'p\x97cu[n\xd3\xca\xca\x88\x8da*\xcb\x02_'

MAC = b"fb92d54b2136c756ee80b2d2d8fd925ceccd09f4"
key_length = 16
message = b"VDU="

def attack(MAC, key_length, message):
    # decode the message
    decoded_message = base64.b64decode(message)

    # append flag to the decoded_message
    new_message = decoded_message + b"flag"

    # generate the new MAC for the new message
    new_MAC = hlextend.new('sha1')
    extended_message = new_MAC.extend('flag', str(decoded_message)[2:-1], key_length, str(MAC)[2:-1])

    # parse the appended_val into bytes
    extended_message = "b'" + extended_message +"'"
    extended_message = eval(extended_message)


    original_message_length = key_length+len(decoded_message)
    sha1_block_size = 64

    # generate the padding to assert that the extended hash is correct
    if original_message_length % sha1_block_size != 0:
        padding = b'\x80' + b'\x00'*(sha1_block_size - original_message_length%sha1_block_size-2) + (8*original_message_length).to_bytes(1, byteorder='big')
    else:
        padding = b""

    # calculate the new MAC assuming that all data is known
    expected_MAC = SHA1.new()
    expected_MAC.update(secret_key + decoded_message+  padding + b"flag")

    # check if the extended MAC is the same as the expected MAC
    assert expected_MAC.hexdigest() == new_MAC.hexdigest()

    # encode the new message in base64
    encoded_message = base64.b64encode(extended_message)


    # check that the extended message hashes to the new_mac
    message_check = SHA1.new()
    message_check.update(secret_key+extended_message)
    
    # check if hashing the extended message will return the new mac
    assert message_check.hexdigest() == new_MAC.hexdigest()

    return (encoded_message, new_MAC.hexdigest())

print(attack(MAC, key_length, message))