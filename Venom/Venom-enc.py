# XOR encrypt (for NT API function names)
import sys
import os
import hashlib
import string
import random

## XOR function to encrypt data
def xor(data, key):
    key = str(key)
    l = len(key)
    output_str = ""

    for i in range(len(data)):
        current = data[i]
        current_key = key[i % len(key)]
        ordd = lambda x: x if isinstance(x, int) else ord(x)
        output_str += chr(ordd(current) ^ ord(current_key))
    return output_str

## encrypting
def xor_encrypt(data, key):
    ciphertext = xor(data, key)
    ciphertext = '{ 0x' + ', 0x'.join(hex(ord(x))[2:] for x in ciphertext) + ' };'
    print (ciphertext, key)
    return ciphertext, key

## key for encrypt/decrypt
nt_duplicate_object = "NtDuplicateObject"
nt_query_sys_info = "NtQuerySystemInformation"
nt_query_obj = "NtQueryObject"

length = random.randint(16, 32)
my_secret_key = ''.join(random.choice(string.ascii_letters) for i in range(length))

## encrypt NT DLL functions
e_nt_duplicate_object, p_key = xor_encrypt(nt_duplicate_object, my_secret_key)
e_nt_query_sys_info, p_key = xor_encrypt(nt_query_sys_info, my_secret_key)
e_nt_query_obj, p_key = xor_encrypt(nt_query_obj, my_secret_key)


