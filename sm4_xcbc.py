#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from gmssl.sm4 import CryptSM4, SM4_ENCRYPT
import binascii

def sm4_xcbc_mac(key, data):

    if len(key) != 16:
        raise ValueError("Key must be 16 bytes (128 bits)")

    def sm4_encrypt(k, plaintext):
        cipher = CryptSM4()
        cipher.set_key(k, SM4_ENCRYPT)
        return cipher.crypt_ecb(plaintext)
    
    K1 = sm4_encrypt(key, b'\x01'*16)  # K1 = SM4(K, 0x0101...01)
    K2 = sm4_encrypt(key, b'\x02'*16)  # K2 = SM4(K, 0x0202...02)
    K3 = sm4_encrypt(key, b'\x03'*16)  # K3 = SM4(K, 0x0303...03)
    

    E_prev = b'\x00'*16
    

    block_size = 16
    blocks = [data[i:i+block_size] for i in range(0, len(data), block_size)]
    
    if not blocks:
        blocks = [b'']
    

    for i in range(len(blocks)-1):
        block = blocks[i]
        if len(block) < block_size:
            block = block.ljust(block_size, b'\x00')
        
        xor_result = bytes(a ^ b for a, b in zip(block, E_prev))
        E_prev = sm4_encrypt(K1, xor_result)
    

    last_block = blocks[-1]
    
    if len(last_block) == block_size:
        # XOR M[n] with E[n-1] and K2
        xor_result = bytes(a ^ b ^ c for a, b, c in zip(last_block, E_prev, K2))
    else:
        padded_block = last_block + b'\x80'  # 0x80 = 10000000

        padded_block = padded_block.ljust(block_size, b'\x00')
        
        # XOR M[n] with E[n-1] and K3
        xor_result = bytes(a ^ b ^ c for a, b, c in zip(padded_block, E_prev, K3))
    
    E_final = sm4_encrypt(K1, xor_result)
    
    mac = E_final[:12]
    
    return mac


if __name__ == "__main__":

    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    
    #test empty input
    empty_data = b""
    mac = sm4_xcbc_mac(key, empty_data)
    print(f"empty input of SM4-XCBC-MAC: {binascii.hexlify(mac).decode()}")
    
    # not empty input
    test_data=bytes.fromhex("0528a41c00000032c70bea2320eac8ff8e6d5aa4bdb9fa2788f8700ec2e27c35921a5c7811bbe526951ababdeb87e08f313876ddd3c1ab4613efb7c7d2f27029d81af822ddd60e9046dc97e7d97137a94504246094cfb622874981440bdc443b3173fc06ad8a5271f16400854fbcae6103020100")
    mac = sm4_xcbc_mac(key, test_data)
    print(f"SM4-XCBC-MAC: {binascii.hexlify(mac).decode()}")
