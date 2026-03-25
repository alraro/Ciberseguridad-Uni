import random
import string

def isUpper(char):
    return char >= 'A' and char <= 'Z'

def isLetter(char):
    return (char >= 'A' and char <= 'Z') or (char >= 'a' and char <= 'z')

def rotateChar(char, shift):
    if (not isLetter(char)):
        return char
    else:
        if isUpper(char):
            offset = ord('A')
        else:
            offset = ord('a')
        return chr((ord(char) - offset + shift) % 26 + offset)

def cesarCypher(cadena, shift, decipher=False):
    """
    Devuelve un descifrado Cesar tradicional (-3) respetando caracteres no alfabéticos. 
    Si decipher es False (por defecto) se cifra, si decipher es True se descifra
    """
    if (shift not in range(1, 26)):
        raise ValueError("Shift debe ser un número entre 1 y 25")
    if (decipher):
        shift = -shift
    resultado = ''
    i = 0
    while i < len(cadena):
        ordenCifrado = rotateChar(cadena[i], shift)
        resultado = resultado + ordenCifrado
        i = i + 1
    return resultado

def testCypher(messageLen, shift, debug=False):
    mensaje = ''.join(random.choices(string.printable, k=messageLen))
    if debug:
        print("Mensaje original: " + mensaje)
    cifrado = cesarCypher(mensaje, shift, decipher=False)
    descifrado = cesarCypher(cifrado, shift, decipher=True)
    if debug:
        print("Mensaje cifrado: " + cifrado)
        print("Mensaje descifrado: " + descifrado)
    if (mensaje == descifrado):
        return True
    else:
        return False

if __name__ == "__main__":
    passed = 0
    failed = 0
    lengths = [1,10,100,1000]
    modulus = 26
    folds = 10
    debug = False
    for i in lengths:
        for j in range(1, modulus):
            for k in range(folds):
                if testCypher(i, j, debug):
                    passed += 1
                else:
                    failed += 1
    for i in (list(range(26, 100)) + [-1, 0]):
        try:
            cesarCypher(10, i)
            failed += 1
        except ValueError:
            passed += 1
    
    if testCypher(0, 3,debug=False):
        passed += 1
    else:
        failed += 1
    print("Tests passed: " + str(passed))
    print("Tests failed: " + str(failed))
    print("Success rate of: " + str(passed/(passed+failed)*100) + "%")