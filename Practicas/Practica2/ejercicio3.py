from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad

class AES_CIPHER_CBC:

	BLOCK_SIZE_AES = 16 # AES: Bloque de 128 bits

	def __init__(self, key):
		"""Inicializa las variables locales"""
		self.key = key

	def cifrar(self, cadena, IV):
		"""Cifra el parámetro cadena (de tipo String) con una IV específica, y 
		   devuelve el texto cifrado binario"""
		cifrador = AES.new(self.key, AES.MODE_CBC, IV)
		cifrado = cifrador.encrypt(pad(cadena.encode("utf-8"), self.BLOCK_SIZE_AES))
		return cifrado

	def descifrar(self, cifrado, IV):
		"""Descifra el parámetro cifrado (de tipo binario) con una IV específica, y 
		   devuelve la cadena en claro de tipo String"""
		descifrador = AES.new(self.key, AES.MODE_CBC, IV)
		descifrado = unpad(descifrador.decrypt(cifrado), self.BLOCK_SIZE_AES).decode("utf-8", "ignore")
		return descifrado

key = get_random_bytes(16)
IV = get_random_bytes(16)

texto_1 = "Hola amigos de la seguridad"
texto_2 = "Hola amigas de la seguridad"

aes_cbc = AES_CIPHER_CBC(key)

cifrado_1 = aes_cbc.cifrar(texto_1, IV)

cifrado_2 = aes_cbc.cifrar(texto_2, IV)

descifrado_1 = aes_cbc.descifrar(cifrado_1, IV)
descifrado_2 = aes_cbc.descifrar(cifrado_2, IV)

print("Texto 1:", texto_1)
print("Texto 1 cifrado (hex):", cifrado_1.hex())
print("Texto 1 descifrado:", descifrado_1)
print()
print("Texto 2:", texto_2)
print("Texto 2 cifrado (hex):", cifrado_2.hex())
print("Texto 2 descifrado:", descifrado_2)
print()
print("¿Los cifrados son iguales?", cifrado_1 == cifrado_2)
