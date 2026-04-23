

from Crypto.Hash import SHA256, HMAC
import base64
import json
import sys
from socket_class import SOCKET_SIMPLE_TCP
import funciones_aes
from Crypto.Random import get_random_bytes

# Paso 0: Inicializacion
########################

# Lee clave KBT
KBT = open("KBT.bin", "rb").read()

# Paso 1) B->T: KBT(Bob, Nb) en AES-GCM
#######################################

# Crear el socket de conexion con T (5551)
print("Creando conexion con T...")
socket = SOCKET_SIMPLE_TCP('127.0.0.1', 5551)
socket.conectar()

# Crea los campos del mensaje
t_n_origen = get_random_bytes(16)

# Codifica el contenido (los campos binarios en una cadena) y contruyo el mensaje JSON
msg_TE = []
msg_TE.append("Bob")
msg_TE.append(t_n_origen.hex())
json_ET = json.dumps(msg_TE)
print("B -> T (descifrado): " + json_ET)

# Cifra los datos con AES GCM
aes_engine = funciones_aes.iniciarAES_GCM(KBT)
cifrado, cifrado_mac, cifrado_nonce = funciones_aes.cifrarAES_GCM(aes_engine,json_ET.encode("utf-8"))

# Envia los datos
socket.enviar(cifrado)
socket.enviar(cifrado_mac)
socket.enviar(cifrado_nonce)

# Paso 2) T->B: KBT(K1, K2, Nb) en AES-GCM
##########################################

# (A realizar por el alumno/a...)

cifrado = socket.recibir()
cifrado_mac = socket.recibir()
cifrado_nonce = socket.recibir()

datos_descifrado = funciones_aes.descifrarAES_GCM(KBT, cifrado_nonce, cifrado, cifrado_mac)

json_descifrado = datos_descifrado.decode("utf-8" ,"ignore")
print("Json descifrado: ", datos_descifrado)
msg_ET = json.loads(json_descifrado)

K1_hex, K2_hex, nb_hex = msg_ET

K1 = bytearray.fromhex(K1_hex)
K2 = bytearray.fromhex(K2_hex)

# Cerramos el socket entre B y T, no lo utilizaremos mas
socket.cerrar() 

# Paso 5) A->B: KAB(Nombre) en AES-CTR con HMAC
###############################################

socket = SOCKET_SIMPLE_TCP('127.0.0.1', 5553)
socket.escuchar()

datos_cifrados = socket.recibir()
nonce_ctr = socket.recibir()
mac = socket.recibir()

verificador = HMAC.new(K2, digestmod=SHA256)
verificador.update(datos_cifrados)
verificador.verify(mac)

aes_descifrado = funciones_aes.iniciarAES_CTR_descifrado(K1, nonce_ctr)
datos_claros = funciones_aes.descifrarAES_CTR(aes_descifrado, datos_cifrados)
print("A -> B (descifrado): " + datos_claros.decode("utf-8", "ignore"))

# Paso 6) B->A: KAB(Apellido) en AES-CTR con HMAC
#################################################

mensaje = "Apellido"
aes_cifrado, nonce_ctr = funciones_aes.iniciarAES_CTR_cifrado(K1)
datos_cifrados = funciones_aes.cifrarAES_CTR(aes_cifrado, mensaje.encode("utf-8"))

mac_engine = HMAC.new(K2, digestmod=SHA256)
mac_engine.update(datos_cifrados)
mac = mac_engine.digest()

socket.enviar(datos_cifrados)
socket.enviar(nonce_ctr)
socket.enviar(mac)
print("B -> A (descifrado): " + mensaje)

# Paso 7) A->B: KAB(END) en AES-CTR con HMAC
############################################

datos_cifrados = socket.recibir()
nonce_ctr = socket.recibir()
mac = socket.recibir()

verificador = HMAC.new(K2, digestmod=SHA256)
verificador.update(datos_cifrados)
verificador.verify(mac)

aes_descifrado = funciones_aes.iniciarAES_CTR_descifrado(K1, nonce_ctr)
datos_claros = funciones_aes.descifrarAES_CTR(aes_descifrado, datos_cifrados)
print("A -> B (descifrado): " + datos_claros.decode("utf-8", "ignore"))

socket.cerrar()

