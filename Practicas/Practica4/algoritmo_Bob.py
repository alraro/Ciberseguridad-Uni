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

# Descifro el mensaje

# Verifico el mac

# Visualizo la identidad del remitente

#####################
#####################

# Genero el json con el nombre de Bob, el de Alice y el nonce nA

# Cifro el json con K1

# Aplico HMAC

# Envío el json cifrado junto con el nonce del AES CTR, y el mac del HMAC

#####################
#####################

# Recibo el primer mensaje de Alice

# Descifro el mensaje


# Verifico el mac

# Muestro el mensaje


# Recibo el segundo mensaje de Alice

# Descifro el mensaje


# Verifico el mac

# Muestro el mensaje


# Cierro el socket
socketserver.cerrar()