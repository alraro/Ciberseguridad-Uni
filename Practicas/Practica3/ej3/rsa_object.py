"""
Codigo APENDICE A
"""
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pss
from Crypto.Hash import SHA256

def crear_RSAKey():
    key = RSA.generate(2048)

    return key

def guardar_RSAKey_Privada(fichero, key, password):
    key_cifrada = key.export_key(passphrase=password, pkcs=8, protection="scryptAndAES128-CBC")
    file_out = open(fichero, "wb")
    file_out.write(key_cifrada)
    file_out.close()

def cargar_RSAKey_Privada(fichero, password):
    key_cifrada = open(fichero, "rb").read()
    key = RSA.import_key(key_cifrada, passphrase=password)

    return key

def guardar_RSAKey_Publica(fichero, key):
    key_pub = key.publickey().export_key()
    file_out = open(fichero, "wb")
    file_out.write(key_pub)
    file_out.close()

def cargar_RSAKey_Publica(fichero):
    keyFile = open(fichero, "rb").read()
    key_pub = RSA.import_key(keyFile)

    return key_pub

def cifrarRSA_OAEP(cadena, key):
    datos = cadena.encode("utf-8")
    engineRSACifrado = PKCS1_OAEP.new(key)
    cifrado = engineRSACifrado.encrypt(datos)

    return cifrado

def descifrarRSA_OAEP(cifrado, key):
    engineRSADescifrado = PKCS1_OAEP.new(key)
    datos = engineRSADescifrado.decrypt(cifrado)
    cadena = datos.decode("utf-8")

    return cadena

def firmarRSA_PSS(texto, key_private):
    h = SHA256.new(texto.encode("utf-8")) # Crea un nuevo objeto SHA 256, pasándole el texto
    print(h.hexdigest()) # Muestra el hash del texto en hexadecimal (NOTA: prueba a poner print(h.digest()) en la siguiente línea...)
    signature = pss.new(key_private).sign(h)

    return signature

def comprobarRSA_PSS(texto, firma, key_public):
    h = SHA256.new(texto.encode("utf-8")) # Crea un nuevo objeto SHA 256, pasándole el texto
    print(h.hexdigest()) # Muestra el hash del texto en hexadecimal (NOTA: prueba a poner print(h.digest()) en la siguiente línea...)
    verifier = pss.new(key_public)
    try:
        verifier.verify(h, firma)
        return True
    except (ValueError, TypeError):
        return False


class RSA_OBJECT:

    def __init__(self):
        """Inicializa un objeto RSA, sin ninguna clave"""
        # Nota: Para comprobar si un objeto (no) ha sido inicializado, hay
        #   que hacer "if self.public_key is None:" 
        self.private_key = None
        self.public_key = None

    def create_KeyPair(self):
        """Crea un par de claves publico/privada, y las almacena dentro de la instancia"""
        key = RSA.generate(2048)
        self.private_key = key
        self.public_key = key.publickey()

    def save_PrivateKey(self, file, password):
        """Guarda la clave privada self.private_key en un fichero file, usando una contraseña password"""
        key_cifrada = self.private_key.export_key(passphrase=password, pkcs=8, protection="scryptAndAES128-CBC")
        file_out = open(file, "wb")
        file_out.write(key_cifrada)
        file_out.close()

    def load_PrivateKey(self, file, password):
        """Carga la clave privada self.private_key de un fichero file, usando una contraseña password"""
        key_cifrada = open(file, "rb").read()
        key = RSA.import_key(key_cifrada, passphrase=password)
        self.private_key = key

        return key

    def save_PublicKey(self, file):
        """Guarda la clave publica self.public_key en un fichero file"""
        key_pub = self.public_key.export_key()
        file_out = open(file, "wb")
        file_out.write(key_pub)
        file_out.close()

    def load_PublicKey(self, file):
        """Carga la clave publica self.public_key de un fichero file"""
        keyFile = open(file, "rb").read()
        key_pub = RSA.import_key(keyFile)
        self.public_key = key_pub
        return key_pub

    def cifrar(self, datos):
        """Cifra el parámetro datos (de tipo binario) con la clave self.public_key, y devuelve
           el resultado. En caso de error, se devuelve None"""
        if self.public_key is None:
            return None
        if isinstance(datos, str):
            datos = datos.encode("utf-8")

        engineRSACifrado = PKCS1_OAEP.new(self.public_key)
        cifrado = engineRSACifrado.encrypt(datos)

        return cifrado
        

    def descifrar(self, cifrado):
        """Descrifra el parámetro cifrado (de tipo binario) con la clave self.private_key, y devuelve
           el resultado (de tipo binario). En caso de error, se devuelve None"""
        if self.private_key is None:
            return None
        engineRSADescifrado = PKCS1_OAEP.new(self.private_key)
        datos = engineRSADescifrado.decrypt(cifrado)
        return datos

    def firmar(self, datos):
        """Firma el parámetro datos (de tipo binario) con la clave self.private_key, y devuelve el 
           resultado. En caso de error, se devuelve None."""
        if self.private_key is None:
            return None
        if isinstance(datos, str):
            datos = datos.encode("utf-8")
        h = SHA256.new(datos) # Crea un nuevo objeto SHA 256, pasándole el texto
        print(h.hexdigest()) # Muestra el hash del texto en hexadecimal (NOTA: prueba a poner print(h.digest()) en la siguiente línea...)
        signature = pss.new(self.private_key).sign(h)

        return signature

    def comprobar(self, text, signature):
        """Comprueba el parámetro text (de tipo binario) con respecto a una firma signature 
           (de tipo binario), usando para ello la clave self.public_key. 
           Devuelve True si la comprobacion es correcta, o False en caso contrario o 
           en caso de error."""
        if self.public_key is None:
            return False

        if isinstance(text, str):
            text = text.encode("utf-8")
        h = SHA256.new(text) # Crea un nuevo objeto SHA 256, pasándole el texto
        print(h.hexdigest()) # Muestra el hash del texto en hexadecimal (NOTA: prueba a poner print(h.digest()) en la siguiente línea...)
        verifier = pss.new(self.public_key)
        try:
            verifier.verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False
