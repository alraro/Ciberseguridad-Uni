from rsa_object import RSA_OBJECT

# Crear clave RSA
# y guardar en ficheros la clave privada (protegida) y publica
password = "password"
private_file = "rsa_key.pem"
public_file = "rsa_key.pub"
RSA_key_creator = RSA_OBJECT()
RSA_key_creator.create_KeyPair()
RSA_key_creator.save_PrivateKey(private_file, password)
RSA_key_creator.save_PublicKey(public_file)
# Crea dos clases, una con la clave privada y otra con la clave publica
RSA_private = RSA_OBJECT()
RSA_public = RSA_OBJECT()
RSA_private.load_PrivateKey(private_file, password)
RSA_public.load_PublicKey(public_file)
# Cifrar y Descifrar con PKCS1 OAEP
cadena = "Lo desconocido es lo contrario de lo conocido. Pasalo."
cifrado = RSA_public.cifrar(cadena.encode("utf‐8"))
print(cifrado)
descifrado = RSA_private.descifrar(cifrado).decode("utf‐8")
print(descifrado)
# Firmar y comprobar con PKCS PSS
firma = RSA_private.firmar(cadena.encode("utf‐8"))
if RSA_public.comprobar(cadena.encode("utf‐8"), firma):
    print("La firma es valida")
else:
    print("La firma es invalida")