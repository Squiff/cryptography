from cipher.aes import AES

# Encrypt
key = bytes.fromhex("000102030405060708090a0b0c0d0e0f") # AES.generate_key(128)
mymessage = AES(key)
mymessage.plaintext = b"Hello World!"
mymessage.encrypt()

print("ENCRYPT")
print("---- Key ----")
print(mymessage.key)
print("---- Message ----")
print(mymessage.plaintext)
print("---- Encrypted Message -----")
print(mymessage.ciphertext.hex())

#  Decrypt
mycipher = AES(key)
mycipher.ciphertext = mymessage.ciphertext
mycipher.decrypt()

print("DECRYPT")
print("---- Key ----")
print(mymessage.key)
print("---- Message ----")
print(mymessage.plaintext)
print("---- Encrypted Message -----")
print(mymessage.ciphertext.hex())