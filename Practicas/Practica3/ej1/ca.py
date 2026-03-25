from baseA import *
import os

PASSWORD = "secret"
TARGETDIR = "./"

def store_key_pair(name):
    keys_dir = TARGETDIR + name + "_keys/"
    if not os.path.isdir(keys_dir):
        os.mkdir(keys_dir)

    clave_priv = crear_RSAKey()

    guardar_RSAKey_Privada(keys_dir + name + "_key.priv", clave_priv, PASSWORD)
    guardar_RSAKey_Publica(keys_dir + name + "_key.pub", clave_priv)

if __name__ == "__main__":
    store_key_pair("Alice")
    store_key_pair("Bob")