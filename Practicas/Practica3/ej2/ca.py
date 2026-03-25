"""
    ca.py
    a. Crear una clave pública y una clave privada RSA de 2048 bits para Alice. Guardar cada clave en un fichero.
    b. Crear una clave pública y una clave privada RSA de 2048 bits para Bob. Guardar cada clave en un fichero.
"""

from baseB import *
import os

PASSWORD = "secret"
TARGETDIR = "./"

def store_key_pair(name):
    keys_dir = TARGETDIR + name + "_keys/"
    if not os.path.isdir(keys_dir):
        os.mkdir(keys_dir)

    clave_priv = crear_ECCKey()

    guardar_ECCKey_Privada(keys_dir + name + "_key.priv", clave_priv, PASSWORD)
    guardar_ECCKey_Publica(keys_dir + name + "_key.pub", clave_priv)

if __name__ == "__main__":
    store_key_pair("Alice")
    store_key_pair("Bob")