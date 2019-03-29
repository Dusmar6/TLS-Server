from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes, hmac
from os import urandom

folderPath = "/Users/SadiqSarwar/Desktop/Lake.jpg"
encPath = "/Users/SadiqSarwar/Desktop/Lake[Encrypted].enc"
decPath = "/Users/SadiqSarwar/Desktop/Lake[Decypted].jpg"
ext = ".jpg"
ivLen = 16
keyLen = 32
padLen = 128
hmacLen = 256


def menu():
    print(" --[Menu]-- ")
    print("1. Encrypt")
    print("2. Decrypt")
    print("3. Exit")

def read(filepath):
    return open(filepath, "rb").read()

def myEncryptMAC(file, key, hkey):
    iv = urandom(ivLen)
    backend = default_backend()
    padder = padding.PKCS7(padLen).padder()
    paddedFile = padder.update(file)
    paddedFile += padder.finalize()
    encryption = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = encryption.encryptor()
    cipherText = encryptor.update(paddedFile) + encryptor.finalize()
    hashfunc = hmac.HMAC(hkey, hashes.SHA256(), backend = default_backend())
    tag = hashfunc.update(cipherText)
    tag = hashfunc.finalize()
    enc = open(encPath, "wb")
    enc.write(cipherText)
    return cipherText, iv, tag

def myFileEncryptMAC():
    filePath = folderPath
    file = read(filePath)
    key = urandom(keyLen)
    hkey = urandom(hmacLen)
    encryptedSet = myEncryptMAC(file, key, hkey)
    return encryptedSet[0], encryptedSet[1], encryptedSet[2], key, hkey, ext

def myDecryptMAC(file, key, iv, tag, hkey):
    backend = default_backend()
    hashfunc = hmac.HMAC(hkey, hashes.SHA256(), backend = default_backend())
    revMes = hashfunc.update(file)
    revMes = hashfunc.verify(tag)
    print(revMes)
    decryption = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = decryption.decryptor()
    paddedFile = decryptor.update(file) + decryptor.finalize()
    unpadder = padding.PKCS7(padLen).unpadder()
    plainText = unpadder.update(paddedFile)
    plainText += unpadder.finalize()
    return plainText

def myFileDecryptMAC(encrypInfo):
    file = read(encPath)
    decryptedSet = myDecryptMAC(file, encrypInfo[3],encrypInfo[1],encrypInfo[2],encrypInfo[4])
    dec = open(decPath, "wb")
    dec.write(decryptedSet)
    
### BELOW AES METHOD WITHOUT HASH

def myEncrypt(file, key):
    iv = urandom(ivLen)
    backend = default_backend()
    padder = padding.PKCS7(padLen).padder()
    paddedFile = padder.update(file)
    paddedFile += padder.finalize()
    encryption = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = encryption.encryptor()
    cipherText = encryptor.update(paddedFile) + encryptor.finalize()
    enc = open(encPath, "wb")
    enc.write(cipherText)
    return cipherText, iv

def myFileEncrypt():
    filePath = folderPath
    file = read(filePath)
    key = urandom(keyLen)
    encryptedSet = myEncrypt(file, key)
    return encryptedSet[0], encryptedSet[1], key, ext

def myDecrypt(file, key, iv):
    backend = default_backend()
    decryption = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = decryption.decryptor()
    paddedFile = decryptor.update(file) + decryptor.finalize()
    unpadder = padding.PKCS7(padLen).unpadder()
    plainText = unpadder.update(paddedFile)
    plainText += unpadder.finalize()
    return plainText


def myFileDecrypt(encrypInfo):
    file = read(encPath)
    decryptedSet = myDecrypt(file, encrypInfo[2],encrypInfo[1])
    dec = open(decPath, "wb")
    dec.write(decryptedSet)

def main():
    encrypInfo = None
    cont = True
    while cont:
        menu()
        choice = int(input("Please Enter Menu Option: "))
        if choice == 1:
            encrypInfo = myFileEncryptMAC()
            print("[File has been encypted]")
            print("--------------------------------\n")
        elif choice == 2:
            myFileDecryptMAC(encrypInfo)
            print("[File has been decrypted]")
            print("--------------------------------\n")
        elif choice == 3:
            print("[Program Terminated]")
            print("--------------------------------\n")
            cont = False
        else:
            print("Invalid Input")

main()