from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes, hmac
from os import urandom

folderPath = ##path for file you'd like to encrypt
encPath = ##folder to place encrypted file
decPath = ##path to file you'd like to decrypt
ext = #file extension

ivLen = 16
keyLen = 32
padLen = 128
hmacLen = 256

##menua
def menu():
    print(" --[Menu]-- ")
    print("1. Encrypt")
    print("2. Decrypt")
    print("3. Exit")

    ##opens file, returns byte array
def read(filepath):
    return open(filepath, "rb").read()

## performs all encryption calculations with CBC mac
def myEncryptMAC(file, key, hkey):
    iv = urandom(ivLen)
    backend = default_backend()
    padder = padding.PKCS7(padLen).padder()
    paddedFile = padder.update(file)## pads the file
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

## opens file and sets up encryption with CBC Mac
def myFileEncryptMAC():
    filePath = folderPath
    file = read(filePath)
    key = urandom(keyLen)
    hkey = urandom(hmacLen)
    encryptedSet = myEncryptMAC(file, key, hkey)
    return encryptedSet[0], encryptedSet[1], encryptedSet[2], key, hkey, ext

##performs CBCMAC decryption
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

##opens file and sets up CBCMAC decrypt
def myFileDecryptMAC(encrypInfo):
    file = read(encPath)
    decryptedSet = myDecryptMAC(file, encrypInfo[3],encrypInfo[1],encrypInfo[2],encrypInfo[4])
    dec = open(decPath, "wb")
    dec.write(decryptedSet)
    
### BELOW AES METHOD WITHOUT HASH

##performs cbc encryption on file
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

##sets up cbc encryption
def myFileEncrypt():
    filePath = folderPath
    file = read(filePath)
    key = urandom(keyLen)
    encryptedSet = myEncrypt(file, key)
    return encryptedSet[0], encryptedSet[1], key, ext

##performs cbc decrytpion
def myDecrypt(file, key, iv):
    backend = default_backend()
    decryption = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = decryption.decryptor()
    paddedFile = decryptor.update(file) + decryptor.finalize()
    unpadder = padding.PKCS7(padLen).unpadder()
    plainText = unpadder.update(paddedFile)
    plainText += unpadder.finalize()
    return plainText

##sets up zes cbc decryption
def myFileDecrypt(encrypInfo):
    file = read(encPath)
    decryptedSet = myDecrypt(file, encrypInfo[2],encrypInfo[1])
    dec = open(decPath, "wb")
    dec.write(decryptedSet)

    ##main menu logic
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
