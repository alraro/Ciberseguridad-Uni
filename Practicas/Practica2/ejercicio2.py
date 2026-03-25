from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

BLOCK_SIZE_AES = 16

key = get_random_bytes(16)
IV = get_random_bytes(16)

mensaje = "Hola amigos de Seguridad"

# ECB

cifrador_ECB = AES.new(key, AES.MODE_ECB)
cifrado_ECB = cifrador_ECB.encrypt(pad(mensaje.encode("utf-8"), BLOCK_SIZE_AES))

descifrador_ECB = AES.new(key, AES.MODE_ECB)
descifrado_ECB = unpad(descifrador_ECB.decrypt(cifrado_ECB), BLOCK_SIZE_AES).decode("utf-8", "ignore")

# CTR
cifrador_CTR = AES.new(key, AES.MODE_CTR, nonce=get_random_bytes(BLOCK_SIZE_AES // 2))
cifrado_CTR = cifrador_CTR.encrypt(mensaje.encode("utf-8"))

descifrador_CTR = AES.new(key, AES.MODE_CTR, nonce=cifrador_CTR.nonce)
descifrado_CTR = descifrador_CTR.decrypt(cifrado_CTR).decode("utf-8", "ignore")

# OFB
cifrador_OFB = AES.new(key, AES.MODE_OFB, iv=IV)
cifrado_OFB = cifrador_OFB.encrypt(pad(mensaje.encode("utf-8"), BLOCK_SIZE_AES))

descifrador_OFB = AES.new(key, AES.MODE_OFB, iv=IV)
descifrado_OFB = unpad(descifrador_OFB.decrypt(cifrado_OFB), BLOCK_SIZE_AES).decode("utf-8", "ignore")

# CFB
cifrador_CFB = AES.new(key, AES.MODE_CFB, iv=IV)
cifrado_CFB = cifrador_CFB.encrypt(pad(mensaje.encode("utf-8"), BLOCK_SIZE_AES))

descifrador_CFB = AES.new(key, AES.MODE_CFB, iv=IV)
descifrado_CFB = unpad(descifrador_CFB.decrypt(cifrado_CFB), BLOCK_SIZE_AES).decode("utf-8", "ignore")

# GCM
cifrador_GCM = AES.new(key, AES.MODE_GCM, nonce=get_random_bytes(BLOCK_SIZE_AES), mac_len=16)
cifrado_GCM = cifrador_GCM.encrypt(mensaje.encode("utf-8"))

descifrador_GCM = AES.new(key, AES.MODE_GCM, nonce=cifrador_GCM.nonce, mac_len=16)
descifrado_GCM = descifrador_GCM.decrypt(cifrado_GCM).decode("utf-8", "ignore")

print("Mensaje:", mensaje)
print("")

print("=====ECB=====")
print("Mensaje cifrado (hex):", cifrado_ECB.hex())
print("Mensaje descifrado:", descifrado_ECB)
print("")

print("=====CTR=====")
print("Mensaje cifrado (hex):", cifrado_CTR.hex())
print("Mensaje descifrado:", descifrado_CTR)
print("")

print("=====OFB=====")
print("Mensaje cifrado (hex):", cifrado_OFB.hex())
print("Mensaje descifrado:", descifrado_OFB)
print("")

print("=====CFB=====")
print("Mensaje cifrado (hex):", cifrado_CFB.hex())
print("Mensaje descifrado:", descifrado_CFB)
print("")

print("=====GCM=====")
print("Mensaje cifrado (hex):", cifrado_GCM.hex())
print("Mensaje descifrado:", descifrado_GCM)