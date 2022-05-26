#!/usr/bin/python
import tkinter as tk
from tkinter import *
from tkinter.ttk import *
import time
from tkinter import filedialog

from tkinter import messagebox
from tkinter.filedialog import askopenfile

import sys
from tinyec import registry
from Crypto.Cipher import AES
import hashlib, secrets
from os.path import exists as file_exists

import pickle

graphical_mode = False

f_types = [('Text Document', '*.txt'),
           ('Encrypt Files', '*.ecc'), ]

filename = "passwords.txt"
filenamePrivateKey = "privateKey.ecc"
value = "--encrypt"

help_text = "Usage: python3 passwordManager.py [OPTION] [FILE]\n" \
            "-d or --decrypt to decrypt passwords\n" \
            "-e or --encrypt to encrypt passwords\n" \
            "-g or --generate to generate private key\n" \
            "-h or --help to display help\n" \
            "-p or --private-key to set path of private key\n" \
            "-v or --version to display version\n" \
            "\nExample:\n\tpython3 passwordManager.py -e password.txt -p privateKey.ecc\n"

help_show_info = ['Help',
                  'Choose an option and a file to encrypt or decrypt\n'
                  'Uplaod your private key file and click "valid"\n']


def open_file(filename):
    try:
        fob = open(filename, 'r')
    except:
        exit("Can't not open file.")
    return fob.read()


class PasswordManager:
    def __init__(self, password, pathFile="passwords.txt",
                 pathPrivateKey="privateKey.ecc"):
        self.pathFile = pathFile
        self.password = password.encode()
        self.curve = registry.get_curve('brainpoolP256r1')
        self.pathPrivateKey = pathPrivateKey
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
        ciphertext, nonce, authTag = self.encrypt_AES_GCM(self.password,
                                                          secretKey)
        ciphertextPubKey = ciphertextPrivKey * self.curve.g
        return (ciphertext, nonce, authTag, ciphertextPubKey)

    def decrypt_ECC(self, encryptedMsg):
        (ciphertext, nonce, authTag, ciphertextPubKey) = encryptedMsg
        sharedECCKey = self.privKey * ciphertextPubKey
        secretKey = self.ecc_point_to_256_bit_key(sharedECCKey)
        plaintext = self.decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey)
        return plaintext

    def getPrivateKey(self):
        if graphical_mode:
            filename = filenamePrivateKey
        else:
            filename = self.pathPrivateKey
        try:
            f = open(filename, "r")
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
        createPass = PasswordManager(str(plainText), "", self.pathPrivateKey)
        encryptedMsg = createPass.encrypt_ECC()
        file = open(filename, 'ab')
        pickle.dump(encryptedMsg, file)
        file.close()
        return "Encrypt file Done !"

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
        return str


class MenuPasswordManager(Tk):
    def __init__(self):
        Tk.__init__(self)
        menubar = MenuBar(self)
        self.config(menu=menubar)
        self.choice_encryption = self.initLabel('Choose Encrypt/Decrypt :')
        self.draw_password_file = self.initLabel('Upload Password File :')
        self.draw_private_key_file = self.initLabel('Upload Private Key File :')
        self.result_validation = self.initLabel('Result Validation :')
        self.button_encrypt = self.initButton("Encrypt", self.encrypt_value)
        self.button_decrypt = self.initButton("Decrypt", self.decrypt_value)
        self.button_password_file = self.initButton("Upload Password File",
                                                    lambda: self.upload_file(),
                                                    20, 'disable')
        self.button_private_key_file = self.initButton("Upload Private Key",
                                                       lambda: self.upload_file_private_key(),
                                                       20, 'disable')
        self.validate_button = self.initButton("Valid",
                                               lambda: self.execute_program(),
                                               20, 'disable')

    def configWindow(self):
        self.title('Password Manager')
        self.geometry('500x750')
        self.resizable(False, False)
        self.config(background='#848482')
        self.columnconfigure(1, weight=3)

    def initLabel(self, text):
        return tk.Label(self, text=text, font=('times', 13, 'bold'))

    def initButton(self, text, command, width=0, state='normal'):
        return tk.Button(self, text=text, command=command, width=width,
                         state=state, activebackground='#8a2be2')

    def geometry_manager_draw(self, name, row, ipadx=40, sticky='NWSE', padx=20,
                              pady=10):
        name.grid(row=row, column=1, sticky=sticky, padx=padx, ipadx=ipadx,
                  pady=pady)

    def init_geometry_manager(self):
        self.geometry_manager_draw(self.choice_encryption, 1, 60)
        self.geometry_manager_draw(self.button_encrypt, 2, ipadx=40, sticky='W',
                                   padx=30)
        self.geometry_manager_draw(self.button_decrypt, 2, ipadx=40, sticky='E',
                                   padx=30)
        self.geometry_manager_draw(self.draw_password_file, 3)
        self.geometry_manager_draw(self.button_password_file, 4)
        self.geometry_manager_draw(self.draw_private_key_file, 5)
        self.geometry_manager_draw(self.button_private_key_file, 6)
        self.geometry_manager_draw(self.result_validation, 7)
        self.geometry_manager_draw(self.validate_button, 8)

    def decrypt_value(self):
        global value
        value = "--decrypt"
        if self.button_password_file['state'] == DISABLED:
            self.button_password_file['state'] = NORMAL

    def encrypt_value(self):
        global value
        value = "--encrypt"
        if self.button_password_file['state'] == DISABLED:
            self.button_password_file['state'] = NORMAL

    def upload_file_private_key(self):
        file = filedialog.askopenfilename(filetypes=f_types)
        pb1 = Progressbar(
            win,
            orient=HORIZONTAL,
            length=300,
            mode='determinate'
        )

        pb1.grid(row=9, columnspan=3, pady=20)
        for i in range(5):
            win.update_idletasks()
            pb1['value'] += 20
            time.sleep(0.5)
        pb1.destroy()
        global filenamePrivateKey
        filenamePrivateKey = file
        Label(win, text="File Uploaded Successfully!", foreground='green').grid(
            row=9, columnspan=3, pady=10)
        self.switch_validated_button()

    def upload_file(self):
        file = filedialog.askopenfilename(filetypes=f_types)
        pb1 = Progressbar(
            win,
            orient=HORIZONTAL,
            length=300,
            mode='determinate'
        )
        print(value)
        pb1.grid(row=9, columnspan=3, pady=20)

        for i in range(5):
            win.update_idletasks()
            pb1['value'] += 20
            time.sleep(0.5)
        pb1.destroy()

        result = ""
        if value == "encrypt":
            result = open_file(file)
        global filename
        filename = file
        if self.button_private_key_file['state'] == DISABLED:
            self.button_private_key_file['state'] = NORMAL
        Label(win, text="File Uploaded Successfully!", foreground='green').grid(
            row=9, columnspan=3, pady=10)
        print(result)

    def switch_validated_button(self):
        if self.validate_button["state"] == DISABLED:
            self.validate_button["state"] = NORMAL

    def clear_textbox(self, text_box):
        text_box.delete(1.0, 'end')

    def execute_program(self, ):
        message = main(value, filename)
        text_box = Text(
            win,
            height=10,
            width=50
        )

        text_box.insert('end', message)
        text_box.grid(row=9, columnspan=3, pady=10)
        Button(
            win,
            text='Clear',
            width=15,
            command=lambda: self.clear_textbox(text_box)
        ).grid(row=10, column=1, sticky='NWSE')


class MenuBar(Menu):
    def __init__(self, ws):
        Menu.__init__(self, ws, background='#ff8000', foreground='black',
                      activebackground='white', activeforeground='black')

        file = Menu(self, tearoff=1, background='#ffcc99',
                    foreground='black')
        file.add_command(label="generate private key",
                         command=lambda: self.generate_private_key_graphical())
        file.add_command(label="Open")
        file.add_command(label="Save")
        file.add_command(label="Save as")
        file.add_separator()
        file.add_command(label="Exit", command=self.quit)
        self.add_cascade(label="File", underline=0, menu=file)

        edit = Menu(self, background='#ffcc99',
                    foreground='black')
        edit.add_command(label="Undo")
        edit.add_separator()
        edit.add_command(label="Cut")
        edit.add_command(label="Copy")
        edit.add_command(label="Paste")
        self.add_cascade(label="Edit", menu=edit)

        minimap = BooleanVar()
        minimap.set(True)
        darkmode = BooleanVar()
        darkmode.set(False)

        view = Menu(self, tearoff=0, background='#ffcc99',
                    foreground='black')
        ratio = Menu(self, tearoff=0, background='#ffcc99',
                     foreground='black')

        for aspected_ratio in ('4:3', '16:9'):
            ratio.add_command(label=aspected_ratio)
        view.add_cascade(label='Ratio', menu=ratio)
        view.add_checkbutton(label="show minimap", onvalue=1, offvalue=0,
                             variable=minimap)
        view.add_checkbutton(label='Darkmode', onvalue=1, offvalue=0,
                             variable=darkmode,
                             command=lambda: self.darkMode(darkmode))
        self.add_cascade(label='View', menu=view)

        help = Menu(self, tearoff=1, background='#ffcc99', foreground='black')
        help.add_command(label="About", command=help_information)
        help.add_separator()
        help.add_command(label="Version", command=help_version)
        self.add_cascade(label="Help", menu=help)

    def exit(self):
        self.exit

    def generate_private_key_graphical(self):
        privateKey = secrets.randbelow(
            registry.get_curve('brainpoolP256r1').field.n)
        result = tk.messagebox.askquestion('Create Private key',
                                           'Do you want replace privateKey.ecc ?')
        if result == 'yes':
            file = open("test.ecc", "w")
            file.write(str(privateKey))
            file.close()

    def darkMode(self, darkmode):
        if darkmode.get() == 1:
            win.config(background='#ffcc99')
        elif darkmode.get() == 0:
            win.config(background='#848482')
        else:
            messagebox.showerror('PythonGuides', 'Something went wrong!')


def main(cmd, pathFile, pathPrivateKey=""):
    encrypt = PasswordManager("", pathFile, pathPrivateKey)
    if "-e" == cmd or "--encrypt" == cmd:
        return encrypt.encryptPassword(pathFile)
    elif "-d" == cmd or "--decrypt" == cmd:
        return encrypt.decryptPasswords(pathFile)
    else:
        help()
        return 84
    print("Done!")
    return 0


def help():
    print(help_text)


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


def about():
    messagebox.showinfo('PythonGuides',
                        'Python Guides aims at providing best practical tutorials')


def help_information():
    messagebox.showinfo(help_show_info[0], help_show_info[1])


def help_version():
    messagebox.showinfo('Version',
                        'Version: 2.1 (Python 3.6.4)\n'
                        'Author: OnsagerHe\n')


if __name__ == "__main__":
    if len(sys.argv) == 2:
        if sys.argv[1] == '--graphical':
            graphical_mode = True
            win = MenuPasswordManager()
            win.configWindow()
            win.init_geometry_manager()
            win.mainloop()
        if (sys.argv[1] == "-h" or sys.argv[1] == "--help"):
            help()
        elif (sys.argv[1] == "-v" or sys.argv[1] == "--version"):
            version()
        elif (sys.argv[1] == "-g" or sys.argv[1] == "--generate"):
            generatePrivateKey()
        else:
            help()
    elif len(sys.argv) == 3:
        main(str(sys.argv[1]), str(sys.argv[2]))
    elif len(sys.argv) == 5:
        if sys.argv[3] == "-p" or sys.argv[3] == "--private-key":
            main(str(sys.argv[1]), str(sys.argv[2]), str(sys.argv[4]))
    else:
        help()
