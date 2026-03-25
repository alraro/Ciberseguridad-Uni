from baseA import *
import os

BASEDIR="./"
PASSWORD="secret"

MESSAGE_DIR="message/"

if __name__ == "__main__":
    nombre = "Bob"
    nombre_destino = "Alice"

    own_private_key = cargar_RSAKey_Privada(BASEDIR + nombre + "_keys/" + nombre + "_key.priv", PASSWORD)
    other_public_key = cargar_RSAKey_Publica(BASEDIR + nombre_destino + "_keys/" + nombre_destino + "_key.pub")

    with open(BASEDIR + MESSAGE_DIR + "mensaje.cipher", "rb") as f:
        cifrada = f.read()
    
    with open(BASEDIR + MESSAGE_DIR + "mensaje.sign", "rb") as f:
        firmada = f.read()

    descifrado = descifrarRSA_OAEP(cifrada, own_private_key)
    print(f"Mensaje descifrado: {descifrado}")

    if comprobarRSA_PSS(descifrado, firmada, other_public_key):
        print(f"El mensaje es correcto en integridad y ha sido enviado por {nombre_destino}")
    else:
        print("La firma del mensaje es incorrecta")


