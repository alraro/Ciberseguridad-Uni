from baseA import *
import os

BASEDIR="./"
PASSWORD="secret"

MESSAGE_DIR="message/"

if __name__ == "__main__":
    nombre = "Alice"
    nombre_destino = "Bob"
    message = "Hola amigos de la seguridad"

    own_private_key = cargar_RSAKey_Privada(BASEDIR + nombre + "_keys/" + nombre + "_key.priv", PASSWORD)
    other_public_key = cargar_RSAKey_Publica(BASEDIR + nombre_destino + "_keys/" + nombre_destino + "_key.pub")

    cifrada = cifrarRSA_OAEP(message, other_public_key)
    firmada = firmarRSA_PSS(message, own_private_key)

    target_dir = BASEDIR + MESSAGE_DIR
    if not os.path.isdir(target_dir):
        os.mkdir(target_dir)

    with open(target_dir + "mensaje.cipher", 'wb') as f:
        f.write(cifrada)
    with open(target_dir + "mensaje.sign", 'wb') as f:
        f.write(firmada)