"""
Codigo APENDICE C
"""

from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
from Crypto.Signature import DSS

# Ver https://pycryptodome.readthedocs.io/en/latest/src/public_key/ecc.html
# Ver https://pycryptodome.readthedocs.io/en/latest/src/signature/dsa.html 

def crear_ECCKey():
    # Use 'NIST P-256'
    key = ECC.generate(curve='p256')
    return key

def guardar_ECCKey_Privada(fichero: str, key: ECC.EccKey, password: str):
    key_cifrada = key.export_key(
        format='PEM',
        passphrase=password,
        protection="PBKDF2WithHMAC-SHA512AndAES128-CBC"
    )
    file_out = open(fichero, "wb")
    file_out.write(key_cifrada.encode("utf-8"))
    file_out.close()

def cargar_ECCKey_Privada(fichero: str, password: str):
    key_cifrada = open(fichero, "rb").read()
    key = ECC.import_key(key_cifrada, passphrase=password, curve_name='p256')

    return key

def guardar_ECCKey_Publica(fichero: str, key: ECC.EccKey):
    key_pub = key.public_key().export_key(format='PEM')
    file_out = open(fichero, "wb")
    file_out.write(key_pub.encode("utf-8"))
    file_out.close()

def cargar_ECCKey_Publica(fichero: str):
    keyFile = open(fichero, "rb").read()
    key_pub = ECC.import_key(keyFile)

    return key_pub

# def cifrarECC_OAEP(cadena, key):
# El cifrado con ECC (ECIES) aun no está implementado
# Por lo tanto, no se puede implementar este método aun en la versión 3.9.7 
#    return cifrado

# def descifrarECC_OAEP(cifrado, key):
# El cifrado con ECC (ECIES) aun no está implementado
# Por lo tanto, no se puede implementar este método aun en la versión 3.9.7 
#    return cadena

def firmarECC_PSS(texto: str, key_private: ECC.EccKey):
    h = SHA256.new(texto.encode("utf-8")) # Crea un nuevo objeto SHA 256, pasándole el texto
    signature = DSS.new(key_private, "fips-186-3").sign(h)

    return signature


def comprobarECC_PSS(texto: str, firma, key_public):
    h = SHA256.new(texto.encode("utf-8"))
    verifier = DSS.new(key_public, "fips-186-3")
    try:
        verifier.verify(h, firma)
        return True
    except (ValueError, TypeError):
        return False