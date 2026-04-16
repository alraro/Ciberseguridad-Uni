from custom_lib import funciones_rsa, funciones_aes
from custom_lib.socket_class import SOCKET_SIMPLE_TCP
from Crypto.Hash import HMAC, SHA256
import json

# Cargo la clave pública de Alice y la clave privada de Bob
Pub_A = funciones_rsa.cargar_RSAKey_Publica("rsa_alice.pub")
Pri_B = funciones_rsa.cargar_RSAKey_Privada("rsa_bob.pem", "bob")

# Creamos el servidor para Bob y recibimos las claves y la firma
socketserver = SOCKET_SIMPLE_TCP('127.0.0.1', 5551)
socketserver.escuchar()

K1_cif = socketserver.recibir()
K2_cif = socketserver.recibir()
K1K2_fir = socketserver.recibir()

# Descifro las claves K1 y K2 con Pri_B
K1 = funciones_rsa.descifrarRSA_OAEP_BIN(K1_cif, Pri_B)
K2 = funciones_rsa.descifrarRSA_OAEP_BIN(K2_cif, Pri_B)

# Compruebo la validez de la firma con Pub_A
if funciones_rsa.comprobarRSA_PSS(K1+K2,K1K2_fir,Pub_A):
    print("Firma de K1||K2 válida")
else:
    print("Firma de K1||K2 NO válida")

#####################
#####################

# Recibo el mensaje, junto con el nonce del AES CTR, y el mac del HMAC

datos_cifrado = socketserver.recibir()
nonce_aes = socketserver.recibir()
mac = socketserver.recibir()

# Descifro el mensaje

aes_descifrado = funciones_aes.iniciarAES_CTR_descifrado(K1, nonce_aes)
datos_descifrado = funciones_aes.descifrarAES_CTR(aes_descifrado, datos_cifrado)

# Verifico el mac

verificador_hmac = HMAC.new(K2, digestmod=SHA256)
verificador_hmac.update(datos_cifrado)

try:
    verificador_hmac.verify(mac)
    print("Mensaje auténtico")
except ValueError:
    print("Mensaje NO auténtico")

# Visualizo la identidad del remitente

mensaje_recibido = json.loads(datos_descifrado.decode("utf-8"))
print("Identidad remitente:", mensaje_recibido[0])
nA = bytearray.fromhex(mensaje_recibido[1])

#####################
#####################

# Genero el json con el nombre de Bob, el de Alice y el nonce nA

mensaje_respuesta = ["Bob", "Alice", nA.hex()]
jStr_respuesta = json.dumps(mensaje_respuesta)

# Cifro el json con K1

aes_cifrado, nonce_aes_resp = funciones_aes.iniciarAES_CTR_cifrado(K1)
datos_cifrado_resp = funciones_aes.cifrarAES_CTR(aes_cifrado, jStr_respuesta.encode("utf-8"))

# Aplico HMAC

cifrador_hmac_resp = HMAC.new(K2, digestmod=SHA256)
cifrador_hmac_resp.update(datos_cifrado_resp)
mac_resp = cifrador_hmac_resp.digest()

# Envío el json cifrado junto con el nonce del AES CTR, y el mac del HMAC

socketserver.enviar(datos_cifrado_resp)
socketserver.enviar(nonce_aes_resp)
socketserver.enviar(mac_resp)

#####################
#####################

# Recibo el primer mensaje de Alice

datos_cifrado1 = socketserver.recibir()
nonce_aes1 = socketserver.recibir()
mac1 = socketserver.recibir()

# Descifro el mensaje

aes_descifrado1 = funciones_aes.iniciarAES_CTR_descifrado(K1, nonce_aes1)
datos_descifrado1 = funciones_aes.descifrarAES_CTR(aes_descifrado1, datos_cifrado1)

# Verifico el mac

verificador_hmac1 = HMAC.new(K2, digestmod=SHA256)
verificador_hmac1.update(datos_cifrado1)

try:
    verificador_hmac1.verify(mac1)
    print("Intercambio 1 - Mensaje recibido:", datos_descifrado1.decode("utf-8"))
except ValueError:
    print("Intercambio 1 - Error de autenticidad")

# Envío respuesta
mensaje1_resp = "Hola Amigos"
aes_cifrado1_resp, nonce_aes1_resp = funciones_aes.iniciarAES_CTR_cifrado(K1)
datos_cifrado1_resp = funciones_aes.cifrarAES_CTR(aes_cifrado1_resp, mensaje1_resp.encode("utf-8"))
cifrador_hmac1_resp = HMAC.new(K2, digestmod=SHA256)
cifrador_hmac1_resp.update(datos_cifrado1_resp)
mac1_resp = cifrador_hmac1_resp.digest()
socketserver.enviar(datos_cifrado1_resp)
socketserver.enviar(nonce_aes1_resp)
socketserver.enviar(mac1_resp)

# Recibo el segundo mensaje de Alice

datos_cifrado2 = socketserver.recibir()
nonce_aes2 = socketserver.recibir()
mac2 = socketserver.recibir()

# Descifro el mensaje

aes_descifrado2 = funciones_aes.iniciarAES_CTR_descifrado(K1, nonce_aes2)
datos_descifrado2 = funciones_aes.descifrarAES_CTR(aes_descifrado2, datos_cifrado2)

# Verifico el mac

verificador_hmac2 = HMAC.new(K2, digestmod=SHA256)
verificador_hmac2.update(datos_cifrado2)

try:
    verificador_hmac2.verify(mac2)
    print("Intercambio 2 - Mensaje recibido:", datos_descifrado2.decode("utf-8"))
except ValueError:
    print("Intercambio 2 - Error de autenticidad")

# Envío respuesta
mensaje2_resp = "Hola Amigos"
aes_cifrado2_resp, nonce_aes2_resp = funciones_aes.iniciarAES_CTR_cifrado(K1)
datos_cifrado2_resp = funciones_aes.cifrarAES_CTR(aes_cifrado2_resp, mensaje2_resp.encode("utf-8"))
cifrador_hmac2_resp = HMAC.new(K2, digestmod=SHA256)
cifrador_hmac2_resp.update(datos_cifrado2_resp)
mac2_resp = cifrador_hmac2_resp.digest()
socketserver.enviar(datos_cifrado2_resp)
socketserver.enviar(nonce_aes2_resp)
socketserver.enviar(mac2_resp)


# Cierro el socket
socketserver.cerrar()