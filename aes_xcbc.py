from Crypto.Cipher import AES

def aes_xcbc_mac(key, data):
    if len(key) != 16:
        raise ValueError("Key must be 16 bytes (128 bits)")
    
    cipher = AES.new(key, AES.MODE_ECB)
    K1 = cipher.encrypt(b'\x01'*16)  # K1 = AES(K, 0x0101...01)
    K2 = cipher.encrypt(b'\x02'*16)  # K2 = AES(K, 0x0202...02)
    K3 = cipher.encrypt(b'\x03'*16)  # K3 = AES(K, 0x0303...03)
    
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
        
        cipher = AES.new(K1, AES.MODE_ECB)
        E_prev = cipher.encrypt(xor_result)
    
    last_block = blocks[-1]
    
    if len(last_block) == block_size:
        # XOR M[n] with E[n-1] and K2
        xor_result = bytes(a ^ b ^ c for a, b, c in zip(last_block, E_prev, K2))
    else:
        padded_block = last_block + b'\x80'  # 0x80 = 10000000
        padded_block = padded_block.ljust(block_size, b'\x00')
        
        # XOR M[n] with E[n-1] and K3
        xor_result = bytes(a ^ b ^ c for a, b, c in zip(padded_block, E_prev, K3))
    
    cipher = AES.new(K1, AES.MODE_ECB)
    E_final = cipher.encrypt(xor_result)
    
    mac = E_final[:12]
    
    return mac


if __name__ == "__main__":
    # RFC 3566
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")

    
    # test empty data
    empty_data = b""
    mac = aes_xcbc_mac(key, empty_data)
    print(f"empty of AES-XCBC-MAC: {mac.hex()}")


    # test not empty
    test_data = bytes.fromhex("0528a41c000000320bf5e4563560c08655be91f11440143dcd22e936fc6ce7ae9d8c05b4be23dbc75f240ade5e7b33bfd5b07f79df15c0bbd99495e95697ee536d5d3f15b77ef804a903da72039bed10f0b63a31a911f59313121110")
    mac = aes_xcbc_mac(key, test_data)
    print(f"authdata of AES-XCBC-MAC: {mac.hex()}")
