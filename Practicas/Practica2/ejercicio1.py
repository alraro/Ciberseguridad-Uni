from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

BLOCK_SIZE_AES = 16

key = get_random_bytes(16)
IV = get_random_bytes(16)

texto_1 = "Hola amigos de la seguridad"
texto_2 = "Hola amigas de la seguridad"

cipher_1 = AES.new(key, AES.MODE_CBC, IV)
cifrado_1 = cipher_1.encrypt(pad(texto_1.encode("utf-8"), BLOCK_SIZE_AES))

cipher_2 = AES.new(key, AES.MODE_CBC, IV)
cifrado_2 = cipher_2.encrypt(pad(texto_2.encode("utf-8"), BLOCK_SIZE_AES))

decipher_1 = AES.new(key, AES.MODE_CBC, IV)
descifrado_1 = unpad(decipher_1.decrypt(cifrado_1), BLOCK_SIZE_AES).decode("utf-8", "ignore")

decipher_2 = AES.new(key, AES.MODE_CBC, IV)
descifrado_2 = unpad(decipher_2.decrypt(cifrado_2), BLOCK_SIZE_AES).decode("utf-8", "ignore")

print("Texto 1:", texto_1)
print("Texto 1 cifrado (hex):", cifrado_1.hex())
print("Texto 1 descifrado:", descifrado_1)
print()
print("Texto 2:", texto_2)
print("Texto 2 cifrado (hex):", cifrado_2.hex())
print("Texto 2 descifrado:", descifrado_2)
print()
print("¿Los cifrados son iguales?", cifrado_1 == cifrado_2)
