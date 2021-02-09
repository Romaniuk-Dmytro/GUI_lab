import hashlib
import json
import os
import pickle
import re
import sys
import winreg

from Crypto.Cipher import DES
from PyQt5.QtCore import QCoreApplication
from PyQt5.QtWidgets import (QAction, QApplication, QLabel, QLineEdit,
                             QMainWindow, QMessageBox, QPushButton,
                             QTableWidget, QTableWidgetItem, QWidget)
from win32api import (GetLogicalDriveStrings, GetSystemDirectory,
                      GetSystemMetrics)


class App(QMainWindow):
    left = 300
    top = 300
    def __init__(self, title = 'kek'):
        super().__init__()
        self.title = title
        self.width = 600
        self.height = 400
        self.setWindowTitle(self.title)
        self.setGeometry(self.left, self.top, self.width, self.height)

        

    def initUI(self):

        txt = QLabel(self)
        txt.setText("Login: ")
        txt.setGeometry(100, 55, 60, 60)

        self.txt2 = QLabel(self)
        self.txt2.setText("Password: ")
        self.txt2.setGeometry(77, 93, 60, 60)

        self.textbox = QLineEdit(self)
        self.textbox.move(150, 70)
        self.textbox.resize(230, 30)

        self.textbox2 = QLineEdit(self)
        self.textbox2.move(150, 110)
        self.textbox2.resize(230, 30)

        self.button = QPushButton('Enter', self)
        self.button.move(200, 170)

        exitAction = QAction('&About', self)
        exitAction.setStatusTip('14 Variant')
        exitAction.triggered.connect(self.bar)

        self.statusBar()

        menubar = self.menuBar()
        fileMenu = menubar.addMenu('&Info')
        fileMenu.addAction(exitAction)

        self.button.clicked.connect(self.autoriz)
        self.show()
        self.window_key()

    def window_key(self):
        self.__init__(title = 'key')
        self.setGeometry(500, 400, 300, 200)

        self.key = QLineEdit(self)
        self.key.move(100, 60)

        self.keybutton = QPushButton('Submit', self)
        self.keybutton.move(100, 90)
        self.keybutton.clicked.connect(self.decrypt_data_base)

        self.show()

    def decrypt_data_base(self):
        self.window_key_value = self.key.text()

        with open('key.txt', 'r') as decrypt_file:
            decrypt_key = decrypt_file.readlines()[0]

        if decrypt_key == self.window_key_value:
            with open('cipher.txt', 'rb') as encrypted_file:
                encrypted_data = pickle.load(encrypted_file)
            os.remove('key.txt')
            os.remove('cipher.txt')

            self.des = DES.new(bytes(decrypt_key, encoding = 'utf-8'), DES.MODE_ECB)
            decrypted = str(self.des.decrypt(encrypted_data))
            decr = decrypted[:0] + decrypted[2:]
            decr = decr[0:-1]
            print(decr)

            with open('users.txt', 'w') as db:
                db.write(decr)

            os.rename('users.txt', 'users.json')
                
            with open("users.json", "r") as fi:
                self.users = json.load(fi)

            self.close()
        else:
            crash = QMessageBox.question(self, 'Incorrect key', 'Input again?', QMessageBox.Yes | QMessageBox.Yes, QMessageBox.No)
            if crash == QMessageBox.Yes:
                self.key.setText("")
            else:    
                sys.exit()


    def bar(self):
        QMessageBox.information(self, "14 Variant", "Наявність цифр, розділового і знаків арифметичних операцій знаків", QMessageBox.Ok, QMessageBox.Ok)
        
    def autoriz(self):
        textboxValue = self.textbox.text()
        textboxValue2 = self.textbox2.text()

        self.user = next((user for user in self.users if user["login"] == textboxValue), False)


        if self.user:
            print(self.user)

            if self.user.get('ban', False):
                QMessageBox.information(self, 'Warning', 'You are banned', QMessageBox.Ok, QMessageBox.Ok)
                self.textbox.setText("")
                self.textbox2.setText("")
            else:    

                if self.user.get('pass', False) == textboxValue2:
                    Result = QMessageBox.question(self, 'Result', 'Hello', QMessageBox.Ok, QMessageBox.Ok)
                    if Result == QMessageBox.Ok:
                        self.close()
                        self.MainWindow()
                else:
                    buttonReply = QMessageBox.question(self, 'Result', "Incorrect Password, input again?", QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
                    if buttonReply == QMessageBox.Yes:
                        self.textbox.setText("")
                        self.textbox2.setText("")
                    else:
                        sys.exit()
        else:
            buttonReply = QMessageBox.question(self, 'Result', "Incorrect Login, input again?", QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if buttonReply == QMessageBox.Yes:
                self.textbox.setText("")
                self.textbox2.setText("")
            else:
                sys.exit()
         
    def MainWindow(self):
        if self.user.get('is_admin'):
            self.__init__(title = "Admin")

            self.button = QPushButton('Change Password', self)
            self.button.move(60, 40)
            self.button.resize(120, 30)

            self.adminbutton = QPushButton('Pass for user', self)
            self.adminbutton.move(60, 80)
            self.adminbutton.resize(120, 30)

            self.btnlist = QPushButton("User list", self)
            self.btnlist.move(60, 120)
            self.btnlist.resize(120, 30)

            self.btnblock = QPushButton("Block user", self)
            self.btnblock.move(350, 40)
            self.btnblock.resize(120, 30)

            self.btnnewuser = QPushButton("Add user", self)
            self.btnnewuser.move(350, 80)
            self.btnnewuser.resize(120, 30)

            self.btnkey = QPushButton('New key', self)
            self.btnkey.move(350, 120)
            self.btnkey.resize(120, 30)

            self.adminbutton.clicked.connect(self.adminrestrictions)
            self.btnblock.clicked.connect(self.ban)    
            self.btnnewuser.clicked.connect(self.addusers)
            self.btnlist.clicked.connect(self.list_of_users)
            self.button.clicked.connect(self.changePass)
            self.btnkey.clicked.connect(self.new_key)

        else:
            self.__init__(title='User')

            self.button = QPushButton('Change Password', self)
            self.button.move(60, 40)
            self.button.resize(120, 30)

            self.button.clicked.connect(self.changePass)

        self.show()


    def new_key(self):
        self.__init__(title = 'New key')
        self.setGeometry(500, 400, 300, 200)

        self.newkey = QLineEdit(self)
        self.newkey.move(100, 60)

        self.newkeybutton = QPushButton('Submit', self)
        self.newkeybutton.move(100, 90)
        self.newkeybutton.clicked.connect(self.new_key_func)

        self.show()
    
    def new_key_func(self):
        new_key_for_encr = self.newkey.text()

        with open('key.txt', 'w') as f:
            f.write(new_key_for_encr)

        with open('users.json', 'r') as plain_file_text:
            plaintext = bytes(plain_file_text.readlines()[0], encoding = 'utf-8')

        while len(plaintext) % 8 != 0:
            plaintext += b' '

        des = DES.new(bytes(new_key_for_encr, encoding = 'utf-8'), DES.MODE_ECB)
        new_cipher_text = des.encrypt(plaintext)

        with open('cipher.txt', 'wb') as cipher_file_text:
            ciphertext = new_cipher_text
            pickle.dump(ciphertext, cipher_file_text)

        os.remove('users.json')
        sys.exit()

    def addusers(self):
        self.__init__(title = "Adding new user")

        self.textboxname = QLineEdit(self)
        self.textboxname.move(150, 60)
        self.textboxname.resize(230, 30)

        self.btnpass = QPushButton("Continue", self)
        self.btnpass.move(210, 110)
        self.btnpass.clicked.connect(self.addusers2_0)


        self.show()

    def addusers2_0(self):
        self.textboxpassValue = self.textboxname.text()
        self.user = next((user for user in self.users if user["login"] == self.textboxpassValue), True)

        if self.textboxpassValue == "":
            QMessageBox.information(self, 'Empty', 'Line is empty, please enter login again', QMessageBox.Ok, QMessageBox.Ok)
            self.textboxname.setText("")
        else:
            with open("users.json", "w+") as newuser:
                # self.user['login'] = self.textboxpassValue
                
                if self.textboxpassValue == next((user for user in self.users)):
                    QMessageBox.information(self, "Error", "Name is already used", QMessageBox.Ok, QMessageBox.Ok)
                    self.textboxname.setText("")
                    self.textboxpassValue = ""
                else:
                    newuserinfo = {'login': self.textboxpassValue, 'pass': "", "is_admin": False, "restrictions": False, "ban": False}
                    self.users.append(newuserinfo)
                newuser.write(json.dumps(self.users))
            QMessageBox.information(self, "Complete", "New user was added", QMessageBox.Ok, QMessageBox.Ok)          
            self.close()

    def ban(self):
        self.__init__(title = "Blocking user")

        self.textboxban = QLineEdit(self)
        self.textboxban.move(150, 60)
        self.textboxban.resize(260, 30)

        self.btnban = QPushButton("Ban", self)
        self.btnban.move(150, 110)
        self.btnban.clicked.connect(self.ban2_0)

        self.btnban = QPushButton("Unban", self)
        self.btnban.move(310, 110)
        self.btnban.clicked.connect(self.ban3_0)


        self.show()

    def ban2_0(self):
        textboxValue = self.textboxban.text()
        value = True

        if textboxValue == "":
            QMessageBox.information(self, 'Empty', 'Line is empty, please enter login again', QMessageBox.Ok, QMessageBox.Ok)
            self.textboxban.setText("")

        else:
            with open('users.json', 'w+') as file:
                for user in self.users:
                    if user['login'] == textboxValue:
                        user['ban'] = True
                        user['ban'] = user.get('ban')
                        QMessageBox.information(self, "Result", "User is banned", QMessageBox.Ok, QMessageBox.Ok)
                         
                file.write(json.dumps(self.users))

        self.close()   

    def ban3_0(self):
        textboxValue = self.textboxban.text()
        # userr = next((user for user in self.users if user["login"] == textboxValue), True)

        if textboxValue == "":
            QMessageBox.information(self, 'Empty', 'Line is empty, please enter login again', QMessageBox.Ok, QMessageBox.Ok)
            self.textboxban.setText("")    

        else:
            with open('users.json', 'w+') as file:
                for user in self.users:
                    if user['login'] == textboxValue:
                        user['ban'] = False
                        user['ban'] = user.get('ban')
                    QMessageBox.information(self, "Result", "User is Unbanned", QMessageBox.Ok, QMessageBox.Ok)    

                file.write(json.dumps(self.users))

        self.close()    

    def changePass(self):
        # вікно для вводу нового пароля
        # вікно для адміна з вибором юзера для зміни пароля
        self.__init__(title = "Changing Password")

        if self.user['restrictions'] == True:
            QMessageBox.information(self, "Warning", "You have restrictions to setting password", QMessageBox.Ok, QMessageBox.Ok)
            self.textboxpass1 = QLineEdit(self)
            self.textboxpass1.move(150, 60)
            self.textboxpass1.resize(230, 30)


            self.textboxpass21 = QLineEdit(self)
            self.textboxpass21.move(150, 100)
            self.textboxpass21.resize(230, 30)

            self.btnpass = QPushButton("Continue", self)
            self.btnpass.move(210, 330)
            self.btnpass.clicked.connect(self.changePass2_0)

            txt = QLabel(self)
            txt.setText("New Password: ")
            txt.setGeometry(10, 42, 110, 60)

            txt2 = QLabel(self)
            txt2.setText("Old Password: ")
            txt2.setGeometry(10, 88, 110, 60)

        else:
            self.textboxpass = QLineEdit(self)
            self.textboxpass.move(150, 60)
            self.textboxpass.resize(230, 30)


            self.textboxpass2 = QLineEdit(self)
            self.textboxpass2.move(150, 100)
            self.textboxpass2.resize(230, 30)

            self.btnpass = QPushButton("Continue", self)
            self.btnpass.move(210, 330)
            self.btnpass.clicked.connect(self.changePass3_0)

            txt = QLabel(self)
            txt.setText("New Password: ")
            txt.setGeometry(10, 42, 110, 60)

            txt2 = QLabel(self)
            txt2.setText("Old Password: ")
            txt2.setGeometry(10, 88, 110, 60)


        self.show()

    def changePass2_0(self):
        self.textboxpassValue = self.textboxpass1.text()
        self.textboxValue2 = self.textboxpass21.text()

        restriction = re.findall(r'[0-9]' and r'[.%,?+=]', self.textboxpassValue)    

        if restriction:
            if self.textboxValue2 == self.user['pass']:
                with open('users.json', 'w+') as file:
                    self.user['pass'] = self.textboxpassValue
                    for user in self.users:
                        if user.get('login') == self.user.get('login'):
                            user['pass'] = self.user.get('pass')
                    file.write(json.dumps(self.users))
            else:
                QMessageBox.information(self, "Error", "Incorrect Password, try again", QMessageBox.Ok, QMessageBox.Ok)
                self.textboxpass.setText("")
                self.textboxpass2.setText("")
        else:
            QMessageBox.information(self, "Error", "Password with restriction", QMessageBox.Ok, QMessageBox.Ok)
            self.textboxpass1.setText("")
            self.textboxpass21.setText("")          
        print(self.user['pass'])

        self.close()

    def changePass3_0(self):
        self.textboxpassValue1 = self.textboxpass.text()
        self.textboxValue21 = self.textboxpass2.text()

        if self.textboxValue21 == self.user['pass']:
            with open('users.json', 'w+') as file:
                self.user['pass'] = self.textboxpassValue1
                for user in self.users:
                    if user.get('login') == self.user.get('login'):
                        user['pass'] = self.user.get('pass')
                file.write(json.dumps(self.users))
        else:
            QMessageBox.information(self, "Error", "Incorrect Password, try again", QMessageBox.Ok, QMessageBox.Ok)
            self.textboxpass.setText("")
            self.textboxpass2.setText("")

        self.close()


    def list_of_users(self):
        self.__init__(title = "List of users")
        x = 0
        self.table = QTableWidget(self)
        self.table.setColumnCount(5)
        self.table.setRowCount(15)
        self.table.setGeometry(0, 0, 600, 400)
        self.table.setHorizontalHeaderLabels(["Login", "Password", "Is Admin", "Restrictons", "Banned"])

        for row in self.users:
            print(row['login'])
            
            self.table.setItem(x, 0, QTableWidgetItem(row['login']))
            self.table.setItem(x, 1, QTableWidgetItem(row['pass']))
            self.table.setItem(x, 2, QTableWidgetItem(str(row['is_admin'])))
            self.table.setItem(x, 3, QTableWidgetItem(str(row['restrictions'])))
            self.table.setItem(x, 4, QTableWidgetItem(str(row['ban'])))

            x += 1
        self.show()

    def adminrestrictions(self):
        self.__init__(title = "Restrictons for user")

        self.textboxrest = QLineEdit(self)
        self.textboxrest.move(150, 60)
        self.textboxrest.resize(280, 30)

        self.btnadmin1 = QPushButton("set restrictions", self)
        self.btnadmin1.move(150, 110)
        self.btnadmin1.clicked.connect(self.adminrestrictions2_0)

        self.btnadmin2 = QPushButton("unset restrictions", self)
        self.btnadmin2.move(310, 110)
        self.btnadmin2.resize(120, 30)
        self.btnadmin2.clicked.connect(self.adminrestrictions3_0)

        self.show()

    def adminrestrictions2_0(self):
        textboxValue = self.textboxrest.text()

        if textboxValue == "":
            QMessageBox.information(self, 'Empty', 'Line is empty, please enter login again', QMessageBox.Ok, QMessageBox.Ok)
            self.textboxrest.setText("")

        else:
            with open('users.json', 'w+') as file:
                for user in self.users:
                    if user['login'] == textboxValue:
                        user['restrictions'] = True
                        user['restrictions'] = user.get('restrictions')
                        QMessageBox.information(self, "Result", "Restrictons is set", QMessageBox.Ok, QMessageBox.Ok)
                         
                file.write(json.dumps(self.users))

        self.close()

    def adminrestrictions3_0(self):
        textboxValue = self.textboxrest.text()

        if textboxValue == "":
            QMessageBox.information(self, 'Empty', 'Line is empty, please enter login again', QMessageBox.Ok, QMessageBox.Ok)
            self.textboxrest.setText("")

        else:
            with open('users.json', 'w+') as file:
                for user in self.users:
                    if user['login'] == textboxValue:
                        user['restrictions'] = False
                        user['restrictions'] = user.get('restrictions')
                        QMessageBox.information(self, "Result", "Restrictons is unset", QMessageBox.Ok, QMessageBox.Ok)
                         
                file.write(json.dumps(self.users))

        self.close()

    def digit(self):
        self.__init__(title = 'error')

        self.error = QLabel(self)
        self.error.setText('error')
        self.error.move(150, 150)

        self.show()

if __name__ == '__main__':
    inf1 = os.environ['COMPUTERNAME']
    inf2 = os.environ['USERNAME']
    inf3 = os.environ['WINDIR']
    inf4 = GetSystemDirectory()
    inf5 = GetSystemMetrics(0)
    inf6 = os.getcwd()
    inf7 = GetLogicalDriveStrings()

    signature = inf1 + inf2 + inf3 + inf4 + inf6 + inf7 + str(inf5)
    sha = hashlib.sha256(signature.encode()).hexdigest()


    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Software\\Romanuik\\Signature", 0, winreg.KEY_READ)
    key_dict = {}
    i = 0
    while True:
        try:
            subvalue = winreg.EnumValue(key, i)
        except WindowsError as e:
            break
        key_dict[subvalue[0]] = subvalue[1:]
        i+=1
    pr_key = key_dict[''][0]

    if str(sha) == str(pr_key):
        app = QApplication(sys.argv)
        ex = App(title='Program 1')
        ex.initUI()
        sys.exit(app.exec_())
    else:
        app = QApplication(sys.argv)
        ex = App(title='Program 1')
        ex.digit()
        sys.exit(app.exec_())        
