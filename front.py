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
           ('Encrypt Files', '*.ecc'),]

def open_file(filename):
    try:
        fob=open(filename,'r')
    except:
        exit("Can't not open file.")
    return fob.read()

def upload_file():
    file = filedialog.askopenfilename(filetypes=f_types)
    pb1 = Progressbar(
            win, 
            orient=HORIZONTAL, 
            length=300, 
            mode='determinate'
            )
    print(value)
    pb1.grid(row=9, columnspan=3, pady=20)
    #pb1.grid(row=5, columnspan=3, pady=20, anchor='center')
    for i in range(5):
        win.update_idletasks()
        pb1['value'] += 20
        time.sleep(0.5)
    pb1.destroy()

    result = ""
    if value == "encrypt":
        result =  open_file(file)
    global filename
    filename = file
    if button_private_key_file['state'] == DISABLED:
        button_private_key_file['state'] = NORMAL
    Label(win, text="File Uploaded Successfully!", foreground='green').grid(row=9, columnspan=3, pady=10)
    print(result)

def upload_file_private_key():
    file = filedialog.askopenfilename(filetypes=f_types)
    pb1 = Progressbar(
            win, 
            orient=HORIZONTAL, 
            length=300, 
            mode='determinate'
            )
    #pb1.place(anchor='center', relx=0.5, rely=0.5)
    pb1.grid(row=9, columnspan=3, pady=20)
    for i in range(5):
        win.update_idletasks()
        pb1['value'] += 20
        time.sleep(0.5)
    pb1.destroy()
    global filenamePrivateKey
    filenamePrivateKey = file
    Label(win, text="File Uploaded Successfully!", foreground='green').grid(row=9, columnspan=3, pady=10)
    switch_validated_button()

filename = "passwords.txt"
filenamePrivateKey = "privateKey.ecc"
value = "--encrypt"

def decrypt_value():
    global value
    value = "--decrypt"
    if button_password_file['state'] == DISABLED:
        button_password_file['state'] = NORMAL
        
def encrypt_value():
    global value
    value = "--encrypt"
    if button_password_file['state'] == DISABLED:
        button_password_file['state'] = NORMAL

class PasswordManager:
    def __init__(self, password, pathFile = "passwords.txt", pathPrivateKey = "privateKey.ecc"):
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
        print (str)
        return str

def main(cmd, pathFile, pathPrivateKey = ""):
    encrypt = PasswordManager("", pathFile, pathPrivateKey)
    if "-e" == cmd or "--encrypt" == cmd:
        return encrypt.encryptPassword(pathFile)
    elif "-d" == cmd or "--decrypt" == cmd:
       return  encrypt.decryptPasswords(pathFile)
    else:
        help()
        return 84
    print("Done!")
    return 0

def help():
    print("Usage: python3 passwordManager.py [OPTION] [FILE]\n")
    print("-d or --decrypt to decrypt passwords")
    print("-e or --encrypt to encrypt passwords")
    print("-g or --generate to generate private key")
    print("-h or --help to display help")
    print("-p or --private-key to set path of private key")
    print("-v or --version to display version")
    print("\nExample:\n\tpython3 passwordManager.py -e password.txt -p privateKey.ecc\n")

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

def generate_private_key_graphical():
    privateKey = secrets.randbelow(
        registry.get_curve('brainpoolP256r1').field.n)
    result = tk.messagebox.askquestion('Create Private key',
                                            'Do you want replace privateKey.ecc ?')
    if result == 'yes':
        file = open("test.ecc", "w")
        file.write(str(privateKey))
        file.close()

def switch_validated_button():
    if validate_button["state"] == DISABLED:
        validate_button["state"] = NORMAL

def clear_textbox(text_box):
    text_box.delete(1.0, 'end')

def execute_program():
    message =  main(value, filename)
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
        command=lambda:clear_textbox(text_box)
    ).grid(row=10, column=1,sticky='NWSE')

def about():
    messagebox.showinfo('PythonGuides',
                        'Python Guides aims at providing best practical tutorials')
def help_information():
    messagebox.showinfo('Help',
                        'Choose an option and a file to encrypt or decrypt\n'
                        'Uplaod your private key file and click "valid"\n')

def help_version():
    messagebox.showinfo('Version',
                        'Version: 2.0 (Python 3.6.4)\n'
                        'Author: OnsagerHe\n')

def darkMode(darkmode):
    if darkmode.get() == 1:
        win.config(background='black')
    elif darkmode.get() == 0:
        win.config(background='#848482')
    else:
        messagebox.showerror('PythonGuides', 'Something went wrong!')

def create_toolbar():

    menubar = Menu(win, background='#ff8000', foreground='black',
                   activebackground='white', activeforeground='black')
    file = Menu(menubar, tearoff=1, background='#ffcc99', foreground='black')
    file.add_command(label="generate private key", command=lambda: generate_private_key_graphical())
    file.add_command(label="Open")
    file.add_command(label="Save")
    file.add_command(label="Save as")
    file.add_separator()
    file.add_command(label="Exit", command=win.quit)
    menubar.add_cascade(label="File", menu=file)

    edit = Menu(menubar, tearoff=0)
    edit.add_command(label="Undo")
    edit.add_separator()
    edit.add_command(label="Cut", command=lambda: print("Cut"))
    edit.add_command(label="Copy")
    edit.add_command(label="Paste")
    menubar.add_cascade(label="Edit", menu=edit)

    minimap = BooleanVar()
    minimap.set(True)
    darkmode = BooleanVar()
    darkmode.set(False)

    view = Menu(menubar, tearoff=0)
    view.add_checkbutton(label="show minimap", onvalue=1, offvalue=0,
                         variable=minimap)
    view.add_checkbutton(label='Darkmode', onvalue=1, offvalue=0,
                         variable=darkmode, command=lambda:darkMode(darkmode))
    menubar.add_cascade(label='View', menu=view)

    help = Menu(menubar, tearoff=1, background='#ffcc99', foreground='black')
    help.add_command(label="About", command=help_information)
    help.add_separator()
    help.add_command(label="Version", command=help_version)
    menubar.add_cascade(label="Help", menu=help)

    win.config(menu=menubar)

    #Label(win, text=return_value, foreground='black').grid(row=9, columnspan=5, pady=10)

if __name__ == "__main__":
    if len(sys.argv) == 2:
        if sys.argv[1] == '--graphical':
            graphical_mode = True
            # Create Window
            win = tk.Tk()
            # Set Window sizw
            win.geometry("500x750")
            # Color Window
            # win.config(bg='#4fe3a5')
            win.config(bg='#848482')
            # Title Window
            win.title('Password Manager')
            # Set font text
            my_font1 = ('times', 13, 'bold')
            # win.columnconfigure(0, weight=1)
            win.columnconfigure(1, weight=3)

            # this represents what you have in the page above
            button_encrypt = tk.Button(win, bd=1, text="Encrypt",
                                       command=encrypt_value,
                                       activebackground='#8a2be2')
            button_decrypt = tk.Button(win, bd=1, text="Decrypt",
                                       command=decrypt_value,
                                       activebackground='#8a2be2')
            # button_decrypt.place(x=400, y=0)
            # button_encrypt.grid(row=0, column=0, sticky=tk.W)
            button_password_file = tk.Button(win, text='Upload Password File',
                                             width=20,
                                             command=lambda: upload_file(),
                                             state=DISABLED,
                                             activebackground='#8a2be2')
            button_private_key_file = tk.Button(win, text='Upload Private Key',
                                                width=20,
                                                command=lambda: upload_file_private_key(),
                                                state=DISABLED,
                                                activebackground='#8a2be2')
            validate_button = tk.Button(win, text='Valid',
                                        width=20, command=lambda: execute_program(),
                                        state="disable", activebackground='#8a2be2')

            choice_encryption = tk.Label(win, text='Choose Encrypt/Decrypt :',
                                         font=my_font1)
            draw_password_file = tk.Label(win, text='Upload Password File :',
                                          font=my_font1)
            draw_private_key_file = tk.Label(win, text='Upload Private Key :',
                                             font=my_font1)
            result_validation = tk.Label(win, text='Validation',
                                         font=my_font1)
            choice_encryption.grid(row=1, column=1, sticky='NWSE', padx=20,
                                   ipadx=60, pady=10)
            button_encrypt.grid(row=2, column=1, sticky='W', padx=30, ipadx=40,
                                pady=10)
            button_decrypt.grid(row=2, column=1, sticky='E', padx=30, ipadx=40)
            draw_password_file.grid(row=3, column=1, sticky='NWSE', padx=20,
                                    ipadx=40)
            button_password_file.grid(row=4, column=1, sticky='NWSE', padx=20,
                                      ipadx=40, pady=10)
            draw_private_key_file.grid(row=5, column=1, sticky='NWSE', padx=20,
                                       ipadx=40)
            button_private_key_file.grid(row=6, column=1, sticky='NWSE', padx=20,
                                         ipadx=40, pady=10)
            result_validation.grid(row=7, column=1, sticky='NWSE', padx=20,
                                   ipadx=40)
            validate_button.grid(row=8, column=1, sticky='NWSE', padx=20, ipadx=40,
                                 pady=10)
            print(win.grid_size())

            create_toolbar()
            win.mainloop()  # Keep the window open
        if (sys.argv[1] == "-h" or sys.argv[1] == "--help"):
            help()
        elif (sys.argv[1] == "-v" or sys.argv[1] == "--version"):
            version()
        elif (sys.argv[1] == "-g" or sys.argv[1] == "--generate"):
            generatePrivateKey()
    elif len(sys.argv) == 3:
        main(str(sys.argv[1]), str(sys.argv[2]))
    elif len(sys.argv) == 5:
        if sys.argv[3] == "-p" or sys.argv[3] == "--private-key":
            main(str(sys.argv[1]), str(sys.argv[2]), str(sys.argv[4]))
    else:
       print("Usage: python3 passwordManager.py [OPTION] [FILE]")
       print("\t-h or --help to display options")
