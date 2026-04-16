from custom_lib import funciones_rsa, funciones_aes, socket_class
from custom_lib.socket_class import SOCKET_SIMPLE_TCP
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes
import json

# Cargo la clave pública de Bob y la clave privada de Alice
Pub_B = funciones_rsa.cargar_RSAKey_Publica("rsa_bob.pub")
Pri_A = funciones_rsa.cargar_RSAKey_Privada("rsa_alice.pem", "alice")

# Genero las dos claves
K1 = funciones_aes.crear_AESKey()
K2 = funciones_aes.crear_AESKey()


# Cifro K1 y K2 con Pub_B
K1_cif = funciones_rsa.cifrarRSA_OAEP_BIN(K1, Pub_B)
K2_cif = funciones_rsa.cifrarRSA_OAEP_BIN(K2, Pub_B)

# Firmo la concatenación de K1 y K2 con Pri_A
K1K2_fir = funciones_rsa.firmarRSA_PSS(K1 + K2, Pri_A)

# Conectamos con el servidor y enviamos a Bob a través del socket
socketclient = SOCKET_SIMPLE_TCP('127.0.0.1', 5551)
socketclient.conectar()

socketclient.enviar(K1_cif)
socketclient.enviar(K2_cif)
socketclient.enviar(K1K2_fir)


#####################
#####################

# Genero el json con el nombre de Alice y un nonce nA

nombre = "Alice"

mensaje = []
nA = get_random_bytes(16)


mensaje.append(nombre)
mensaje.append(nA.hex())
jStr = json.dumps(mensaje)

# Cifro el json con K1

aes_cifrado, nonce_aes = funciones_aes.iniciarAES_CTR_cifrado(K1)

datos_cifrado = funciones_aes.cifrarAES_CTR(aes_cifrado, jStr.encode("utf-8"))


# Aplico HMAC

cifrador_hmac = HMAC.new(K2, digestmod=SHA256)
cifrador_hmac.update(datos_cifrado)
mac = cifrador_hmac.digest()

# Envío el json cifrado junto con el nonce del AES CTR, y el mac del HMAC

socketclient.enviar(datos_cifrado)
socketclient.enviar(nonce_aes)
socketclient.enviar(mac)

#####################
#####################

# Recibo el mensaje, junto con el nonce del AES CTR, y el mac del HMAC

datos_cifrado_recibido = socketclient.recibir()
nonce_aes_recibido = socketclient.recibir()
mac_recibido = socketclient.recibir()

# Descifro el mensaje

datos_descifrado = funciones_aes.descifrarAES_CTR(funciones_aes.iniciarAES_CTR_descifrado(K1, nonce_aes_recibido), datos_cifrado_recibido)

# Verifico el mac

verificador_hmac = HMAC.new(K2, digestmod=SHA256)
verificador_hmac.update(datos_cifrado_recibido)

try:
    verificador_hmac.verify(mac_recibido)
    print("El mensaje es auténtico")
except ValueError:
    print("El mensaje no es auténtico")

# Visualizo la identidad del remitente y compruebo si los campos enviados son los mismo que los recibidos

mensaje_recibido = json.loads(datos_descifrado.decode("utf-8"))
print("Identidad remitente:", mensaje_recibido[0])
nA_recibido = bytearray.fromhex(mensaje_recibido[2])

if mensaje_recibido[0] == "Bob" and mensaje_recibido[1] == "Alice" and nA_recibido == nA:
    print("Correcto")
else:
    print("Mal")

#####################
#####################

# Intercambio de información NUMERO 1. Envío "Hola Amigas"

mensaje1 = "Hola Amigas"
aes_cifrado1, nonce_aes1 = funciones_aes.iniciarAES_CTR_cifrado(K1)
datos_cifrado1 = funciones_aes.cifrarAES_CTR(aes_cifrado1, mensaje1.encode("utf-8"))

cifrador_hmac1 = HMAC.new(K2, digestmod=SHA256)
cifrador_hmac1.update(datos_cifrado1)
mac1 = cifrador_hmac1.digest()

socketclient.enviar(datos_cifrado1)
socketclient.enviar(nonce_aes1)
socketclient.enviar(mac1)

# Recibo respuesta de Bob
datos_cifrado1_resp = socketclient.recibir()
nonce_aes1_resp = socketclient.recibir()
mac1_resp = socketclient.recibir()

datos_descifrado1_resp = funciones_aes.descifrarAES_CTR(funciones_aes.iniciarAES_CTR_descifrado(K1, nonce_aes1_resp), datos_cifrado1_resp)
verificador_hmac1 = HMAC.new(K2, digestmod=SHA256)
verificador_hmac1.update(datos_cifrado1_resp)

try:
    verificador_hmac1.verify(mac1_resp)
    print("Intercambio 1 - Mensaje recibido:", datos_descifrado1_resp.decode("utf-8"))
except ValueError:
    print("Intercambio 1 - Error de autenticidad")

# Intercambio de información NUMERO 2. Envío "Hola Amigas" nuevamente

mensaje2 = "Hola Amigas"
aes_cifrado2, nonce_aes2 = funciones_aes.iniciarAES_CTR_cifrado(K1)
datos_cifrado2 = funciones_aes.cifrarAES_CTR(aes_cifrado2, mensaje2.encode("utf-8"))

cifrador_hmac2 = HMAC.new(K2, digestmod=SHA256)
cifrador_hmac2.update(datos_cifrado2)
mac2 = cifrador_hmac2.digest()

socketclient.enviar(datos_cifrado2)
socketclient.enviar(nonce_aes2)
socketclient.enviar(mac2)

# Recibo respuesta de Bob
datos_cifrado2_resp = socketclient.recibir()
nonce_aes2_resp = socketclient.recibir()
mac2_resp = socketclient.recibir()

datos_descifrado2_resp = funciones_aes.descifrarAES_CTR(funciones_aes.iniciarAES_CTR_descifrado(K1, nonce_aes2_resp), datos_cifrado2_resp)
verificador_hmac2 = HMAC.new(K2, digestmod=SHA256)
verificador_hmac2.update(datos_cifrado2_resp)

try:
    verificador_hmac2.verify(mac2_resp)
    print("Intercambio 2 - Mensaje recibido:", datos_descifrado2_resp.decode("utf-8"))
except ValueError:
    print("Intercambio 2 - Error de autenticidad")


# Cierro el socket
socketclient.cerrar()