#!/usr/bin/python

import sys
from tinyec import registry
from Crypto.Cipher import AES
import hashlib, secrets
from os.path import exists as file_exists

import pickle

class PasswordManager:
    def __init__(self, password, pathFile = "passwords.txt"):
        self.pathFile = pathFile
        self.password = password.encode()
        self.curve = registry.get_curve('brainpoolP256r1')
        self.privKey = self.getPrivateKey()
        self.pubKey = self.privKey * self.curve.g

    def encrypt_AES_GCM(self, msg, secretKey):
        aesCipher = AES.new(secretKey, AES.MODE_GCM)
        ciphertext, authTag = aesCipher.encrypt_and_digest(msg)
        return (ciphertext, aesCipher.nonce, authTag)

    def decrypt_AES_GCM(self, ciphertext, nonce, authTag, secretKey):
        aesCipher = AES.new(secretKey, AES.MODE_GCM, nonce)
        plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
        return plaintext

    def ecc_point_to_256_bit_key(self, point):
        sha = hashlib.sha256(int.to_bytes(point.x, 32, 'big'))
        sha.update(int.to_bytes(point.y, 32, 'big'))
        return sha.digest()

    def encrypt_ECC(self):
        ciphertextPrivKey = secrets.randbelow(self.curve.field.n)
        sharedECCKey = ciphertextPrivKey * self.pubKey
        secretKey = self.ecc_point_to_256_bit_key(sharedECCKey)
        ciphertext, nonce, authTag = self.encrypt_AES_GCM(self.password, secretKey)
        ciphertextPubKey = ciphertextPrivKey * self.curve.g
        return (ciphertext, nonce, authTag, ciphertextPubKey)

    def decrypt_ECC(self, encryptedMsg):
        (ciphertext, nonce, authTag, ciphertextPubKey) = encryptedMsg
        sharedECCKey = self.privKey * ciphertextPubKey
        secretKey = self.ecc_point_to_256_bit_key(sharedECCKey)
        plaintext = self.decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey)
        return plaintext

    def getPrivateKey(self):
        try:
            f = open("privateKey.ecc", "r")
            try:
                privateKey = int(f.read())
            except ValueError:
                exit("Can't read private key")
        except IOError:
            exit("Private key file does not exist!")
        return privateKey

    def getPlaintext(self, fileName):
        try:
            f = open(fileName, "r")
            try:
                plainText = f.read()
            except ValueError:
                exit("Can't read password")
        except IOError:
            exit("File does not exist!")
        array = plainText.split("\n")
        for i in range(len(array)):
            array[i] = array[i].split(":")
        return array

    def encryptPassword(self, pathFile):
        plainText = self.getPlaintext(pathFile)
        filename = pathFile
        if file_exists(filename):
            open(filename, 'w').close()
        createPass = PasswordManager(str(plainText))
        encryptedMsg = createPass.encrypt_ECC()
        file = open(filename, 'ab')
        pickle.dump(encryptedMsg, file)
        file.close()

    def decryptPasswords(self, pathFile):
        student = []
        file = open(pathFile, 'rb')
        student.append(pickle.load(file))
        file.close()
        try:
            decryptedMsg = self.decrypt_ECC(student[0])
        except ValueError:
            exit("Impossible to decrypt, wrong private key ...")
        str = (decryptedMsg.decode('utf-8'))
        print(str)

def main(cmd, pathFile):
    encrypt = PasswordManager("", pathFile)
    if "-e" == cmd or "--encrypt" == cmd:
        encrypt.encryptPassword(pathFile)
    elif "-d" == cmd or "--decrypt" == cmd:
        encrypt.decryptPasswords(pathFile)
    else:
        help()
        return 84
    print("Done!")
    return 0

def help():
    print("Usage: python3 passwordManager.py [OPTION] [FILE]")
    print("-d or --decrypt to decrypt passwords")
    print("-e or --encrypt to encrypt passwords")
    print("-g or --generate to generate private key")
    print("-h or --help to display help")
    print("-v or --version to display version")

def version():
    print("Version: 1.0 (Python 3.6.4)")
    print("Author: OnsagerHe")

def generatePrivateKey():
    print("Generating a new private key...")
    privateKey = secrets.randbelow(
        registry.get_curve('brainpoolP256r1').field.n)
    print("Private key: " + str(privateKey))
    print("Saving private key...")
    file = open("privateKey.ecc", "w")
    file.write(str(privateKey))
    file.close()
    print("Private key save in privateKey.ecc file !")

if __name__ == "__main__":
    if len(sys.argv) == 2:
        if (sys.argv[1] == "-h" or sys.argv[1] == "--help"):
            help()
        elif (sys.argv[1] == "-v" or sys.argv[1] == "--version"):
            version()
        elif (sys.argv[1] == "-g" or sys.argv[1] == "--generate"):
            generatePrivateKey()
    elif len(sys.argv) == 3:
        main(str(sys.argv[1]), str(sys.argv[2]))
    else:
        print("Usage: python3 passwordManager.py [OPTION] [FILE]")
        print("\t-h or --help to display options")