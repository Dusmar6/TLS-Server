from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes, hmac
from cryptography.hazmat.primitives.asymmetric import padding as paddings
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from os import urandom
from os import path
import os.path

import base64
import json

directory = "C:\\Users\\dusma\\Desktop\\CryptoFiles\\"
folderPath = "C:\\Users\\dusma\\Desktop\\CryptoFiles\\image.jpg"
encPath = "C:\\Users\\dusma\\Desktop\\CryptoFiles\\image[enc].jpg"
decPath = "C:\\Users\\dusma\\Desktop\\CryptoFiles\\image[dec].jpg"
RSA_publicKey_filepath = "C:\\Users\\dusma\\Desktop\\RSA_Public_Key.pem"
RSA_privateKey_filepath = "C:\\Users\\dusma\\Desktop\\RSA_Private_Key.pem"
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
    
    '''
    #Generate key
    #public_exponent = Fermat Prime # to use as exponent for new key. Recommended: 65537
    #key_size = Bit length of key
    #backend = Implements RSABackend
    '''
def retrieveRSAKeys():
    PrivateKeyExists = path.isfile(RSA_privateKey_filepath)
    PublicKeyExists = path.isfile(RSA_publicKey_filepath)
    
    if PrivateKeyExists and PublicKeyExists:
        print("[File was found in path - Keys have been loaded]")
        with open(RSA_privateKey_filepath, "rb") as key_file:
            privateKey = serialization.load_pem_private_key(key_file.read(),
                                                             password=None,
                                                             backend=default_backend())
        with open(RSA_publicKey_filepath, "rb") as key_file:
            publicKey = serialization.load_pem_public_key(key_file.read(),
                                                             backend=default_backend())    
            
        return publicKey, privateKey
    
    else:
        print("[File was not found in path - Generating new keys]")
        #Generate Private Key
        privateKey = rsa.generate_private_key(public_exponent = 65537,
                                              key_size = 4096,
                                              backend = default_backend())
        #Encode Private Key into PEM File
        pem = privateKey.private_bytes(encoding = serialization.Encoding.PEM,
                                       format = serialization.PrivateFormat.TraditionalOpenSSL,
                                       encryption_algorithm = serialization.NoEncryption())
        pem.splitlines()[0]
        
        #Open File Path for Private Key
        privateKeySave = open(RSA_privateKey_filepath, "wb")
        #Save Private Key to Path
        privateKeySave.write(pem)
        #Close File
        privateKeySave.close()
        
        
        #Generate Public Key
        publicKey = privateKey.public_key()
        #Enclode Public Key into PEM file
        pem = publicKey.public_bytes(encoding = serialization.Encoding.PEM,
                                     format = serialization.PublicFormat.SubjectPublicKeyInfo)
        pem.splitlines()[0]
        
        #Open File Path for Private Key
        publicKeySave = open(RSA_publicKey_filepath, "wb")
        #Save Private Key to Path
        publicKeySave.write(pem)
        #Close File
        publicKeySave.close()
        
        return publicKey, privateKey
        
    
def myRSAEncrypt(filepath):
    
    #Load Encryption Information
    encrypInfo = myFileEncryptMAC(filepath)
    
    #Load from RSA Keys from File Path
    RSA_KeyInfo = retrieveRSAKeys()
    publicKey = RSA_KeyInfo[0]
    privateKey = RSA_KeyInfo[1]
    
    #concatenating keys
    key = encrypInfo[3] + encrypInfo[4]
    
    #encrypt key variable
    RSA_CipherText = publicKey.encrypt(key, paddings.OAEP(
            mgf = paddings.MGF1(algorithm = hashes.SHA256()),
            algorithm = hashes.SHA256(),
            label = None))
    
    #rename encryp info
    C = encrypInfo[0]
    IV = encrypInfo[1]
    tag = encrypInfo[2]
    ext = encrypInfo[5]
    
    #naming encrypted file
    temp = filepath[0:-4]
    encDest = temp + "[enc].json"
    
    #formatting and encoding data for JSON file
    data = {}
    data['file'] = []
    data['file'].append({
        'RSA_CipherText': str(RSA_CipherText, 'cp437'),
        'C': str(C, 'cp437'),
        'IV': str(IV, 'cp437'),
        'tag': str(tag, 'cp437'),
        'ext': ext
            })
    
  
    #write data to json file
    with open(encDest,"w") as write_file:
        json.dump(data, write_file)

    #removes og file
    os.remove(filepath)
    
    print("RSA Encryption Complete")
    return encDest


def myRSADecrypt(filepath):
    
    #Load from RSA Keys from File Path
    RSA_KeyInfo = retrieveRSAKeys()
    publicKey = RSA_KeyInfo[0]
    privateKey = RSA_KeyInfo[1]
    
    
    #load data from JSON file
    with open(filepath) as json_file:
        data = json.load(json_file)
        for f in data['file']:
            RSA_CipherText = bytes(f['RSA_CipherText'], 'cp437')
            C = bytes(f['C'], 'cp437')
            IV = bytes(f['IV'], 'cp437')
            tag = bytes(f['tag'], 'cp437')
            ext = f['ext']

    #Decrypting Key Variable
    RSA_PlainText = privateKey.decrypt(
            RSA_CipherText,
            paddings.OAEP(
            mgf=paddings.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None))
    
    #de-concatenate the keys
    key = RSA_PlainText[0:keyLen]
    hkey = RSA_PlainText[keyLen:]
    
    #run file decryption
    m = myDecryptMAC(C, IV, tag, key, hkey)
    
    #naming decrypted file
    decDest = filepath[0:-10] + "[dec]" + ext
    
    #writing decrypted file
    dec = open(decDest, "wb")
    dec.write(m)
    
    #removes og file
    os.remove(filepath)
    
    print("RSA Decryption Complete")
    return RSA_PlainText


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
    return cipherText, iv, tag

def myFileEncryptMAC(filepath):
    file = read(filepath)
    key = urandom(keyLen)
    hkey = urandom(hmacLen)
    extension = os.path.splitext(filepath)[1]
    encryptedSet = myEncryptMAC(file, key, hkey)
    return encryptedSet[0], encryptedSet[1], encryptedSet[2], key, hkey, extension

'''
def myFileEncryptMAC():
    filePath = folderPath
    file = read(filePath)
    key = urandom(keyLen)
    hkey = urandom(hmacLen)
    #print(file)
    encryptedSet = myEncryptMAC(file, key, hkey)
    return encryptedSet[0], encryptedSet[1], encryptedSet[2], key, hkey, ext
'''

def myDecryptMAC(C, iv, tag, key, hkey):
    backend = default_backend()
    hashfunc = hmac.HMAC(hkey, hashes.SHA256(), backend = default_backend())
    revMes = hashfunc.update(C)
    revMes = hashfunc.verify(tag)
    if(revMes == None):
        print("[Verification has proceeded successfully]")
    else:
        print("[Error: " + revMes + "]")
    decryption = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = decryption.decryptor()
    paddedFile = decryptor.update(C) + decryptor.finalize()
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
'''
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
'''

def main():
    
    #file walking
    for root, dirs, files in os.walk(directory):
        for file in files:
            filepath = (os.path.join(root, file))
            
            #encrypt file
            myRSAEncrypt(filepath)
            
            
    enter = input("Press enter to decrypt")
    
    for root, dirs, files in os.walk(directory):
        for file in files:
            filepath = (os.path.join(root, file))
            
            #decrypt file
            myRSADecrypt(filepath)
         
    
    
'''

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
    '''

main()
