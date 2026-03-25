from baseB import *
import os

BASEDIR="./"
PASSWORD="secret"

MESSAGE_DIR="message/"

if __name__ == "__main__":
    nombre = "Bob"
    nombre_destino = "Alice"

    own_private_key = cargar_ECCKey_Privada(BASEDIR + nombre + "_keys/" + nombre + "_key.priv", PASSWORD)
    other_public_key = cargar_ECCKey_Publica(BASEDIR + nombre_destino + "_keys/" + nombre_destino + "_key.pub")

    with open(BASEDIR + MESSAGE_DIR + "mensaje.sign", "rb") as f:
        firmada = f.read()

    message = "Hola amigos de la seguridad"

    if comprobarECC_PSS(message, firmada, other_public_key):
        print(f"El mensaje es correcto en integridad y ha sido enviado por {nombre_destino}")
    else:
        print("La firma del mensaje es incorrecta")


