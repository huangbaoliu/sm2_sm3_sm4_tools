from gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT

key = b'1234567891234567'
value = b'1234567'
value1 = b'1234567812345678'
iv = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
crypt_sm4 = CryptSM4()

crypt_sm4.set_key(key, SM4_ENCRYPT)
encrypt_value = crypt_sm4.crypt_ecb(value)
crypt_sm4.set_key(key, SM4_DECRYPT)
print("encrypt_value: ", encrypt_value.hex().upper())
decrypt_value = crypt_sm4.crypt_ecb(encrypt_value)
assert value == decrypt_value

crypt_sm4.set_key(key, SM4_ENCRYPT)
enc = crypt_sm4.crypt_ecb_nopad(value1)
print("enc: ", enc.hex().upper())
crypt_sm4.set_key(key, SM4_ENCRYPT)
encrypt_value = crypt_sm4.crypt_cbc(iv , value)
crypt_sm4.set_key(key, SM4_DECRYPT)
decrypt_value = crypt_sm4.crypt_cbc(iv , encrypt_value)
assert value == decrypt_value

