# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'test1.ui'
#
# Created by: PyQt5 UI code generator 5.13.0
#
# WARNING! All changes made in this file will be lost!

import sys
from PyQt5.uic import loadUi
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtWidgets import QApplication, QWidget, QMessageBox
from gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT
from gmssl import sm3, func
import base64
import binascii
from gmssl import sm2, func

crypt_sm4 = CryptSM4()

class cipherToolsUI(QWidget):

    def __init__(self):
        super(cipherToolsUI, self).__init__()
        loadUi('sm_cipher_tools.ui', self)

        self.clear_input_Button.clicked.connect(self.clear_input)
        self.sm4_encrypt_Button.clicked.connect(self.sm4_encrypt)
        self.sm4_decrypt_Button.clicked.connect(self.sm4_decrypt)

        self.sm3_Button.clicked.connect(self.sm3_hash_func)

        self.gen_keypair_Button.clicked.connect(self.sm2_key_pair_func)
        self.sm2_encrypt_Button.clicked.connect(self.sm2_encrypt_func)
        self.sm2_decrypt_Button.clicked.connect(self.sm2_decrypt_func)
        self.sm2_sign_Button.clicked.connect(self.sm2_sign_func)
        self.sm2_verify_Button.clicked.connect(self.sm2_verify_func)

        self.plaintext.textEdited.connect(self.msg_to_hex)
        self.plaintext_hex.textEdited.connect(self.plaintext_hex_input)
        self.privkey.textChanged.connect(self.privkey_input)
        self.pubkx_LE.textChanged.connect(self.pubkxy_to_pubk)
        self.pubky_LE.textChanged.connect(self.pubkxy_to_pubk)
        self.pubkall_LE.textChanged.connect(self.pubkall_input)
        self.id_iv.textChanged.connect(self.id_iv_input)

        #sm4 padding
        self.pad = False
        self.pad_checkBox.setChecked(False)
        self.pad_checkBox.stateChanged.connect(self.sm4_pad)

        #sm4 mode
        self.mode = self.mode_comboBox.currentText()
        self.mode_comboBox.currentIndexChanged.connect(self.mode_changed)

    def Qmsgbox_show(self, type, info):
        QMessageBox.about(self, type, info)

    def mode_changed(self):
        self.mode = self.mode_comboBox.currentText()

    def sm4_pad(self):
        if self.pad_checkBox.isChecked():
            self.pad = True
        else:
            self.pad = False

    def is_hex_char(self, c):
        vl = ord(c)
        if ((vl > 0x2f) & (vl < 0x3a)):
            return True
        elif ((vl > 0x40) & (vl < 0x47)):
            return True
        elif ((vl > 0x60) & (vl < 0x67)):
            return True
        else:
            return False

    def is_hex_string(self, str):
        for i in range(len(str)):
            if (True != self.is_hex_char(str[i])):
                return False
        return True

    def privkey_input(self):
        pvk_str = self.privkey.text().strip()
        if True != self.is_hex_string(pvk_str):
            self.privkey.setText(pvk_str[0:len(pvk_str) - 1].upper())
            self.Qmsgbox_show("Error", "Please input hex number")
            return
        self.privkey.setText(pvk_str.upper())

    def pubkxy_to_pubk(self):
        pubx_str = self.pubkx_LE.text().strip()
        if True != self.is_hex_string(pubx_str):
            self.pubkx_LE.setText(pubx_str[0:len(pubx_str) - 1].upper())
            self.Qmsgbox_show("Error", "Please input hex number")
            return
        self.pubkx_LE.setText(pubx_str.upper())

        puby_str = self.pubky_LE.text().strip()
        if True != self.is_hex_string(puby_str):
            self.pubky_LE.setText(puby_str[0:len(puby_str) - 1].upper())
            self.Qmsgbox_show("Error", "Please input hex number")
            return
        self.pubky_LE.setText(puby_str.upper())

        pubkall = pubx_str + puby_str
        if True == self.is_hex_string(pubkall):
            self.pubkall_LE.setText(pubkall.upper())
        else:
            self.Qmsgbox_show("Error", "Please input hex number")
            self.pubkall_LE.setText("")
            return

    def pubkall_input(self):
        public_key = self.pubkall_LE.text().strip()
        if (True != self.is_hex_string(public_key)):
            self.pubkall_LE.setText(public_key[0:len(public_key) - 1].upper())
            self.Qmsgbox_show("Error", "Please input hex number")
            return
        self.pubkall_LE.setText(public_key.upper())
        self.msg_pubk_id_to_e()

    def msg_to_hex(self):
        plaintext_msg = bytes(self.plaintext.text().strip(), 'ascii')
        self.plaintext_hex.setText(plaintext_msg.hex().upper())
        self.msg_pubk_id_to_e()

    def plaintext_hex_input(self):
        self.plaintext.setText("")
        plaintext_hex_str = self.plaintext_hex.text().strip()
        if True != self.is_hex_string(plaintext_hex_str):
            self.plaintext_hex.setText(plaintext_hex_str[0:len(plaintext_hex_str)-1].upper())
            self.Qmsgbox_show("Error", "Please input hex number")
            return
        self.plaintext_hex.setText(plaintext_hex_str.upper())
        self.msg_pubk_id_to_e()

    def id_iv_input(self):
        id_iv_str = self.id_iv.text().strip()
        if True != self.is_hex_string(id_iv_str):
            self.id_iv.setText(id_iv_str[0:len(id_iv_str) - 1].upper())
            self.Qmsgbox_show("Error", "Please input hex number")
            return
        self.id_iv.setText(id_iv_str.upper())
        self.msg_pubk_id_to_e()

    def msg_pubk_id_to_e(self):
        public_key = self.pubkall_LE.text().strip()
        if len(public_key) != 128:
            return

        sm2_msg = self.plaintext_hex.text().strip()
        if len(sm2_msg) == 0:
            return

        if len(sm2_msg) % 2 != 0:
            sm2_msg = sm2_msg[0:len(sm2_msg) - 1]

        if self.id_iv.text().strip() == "":
            ida = "31323334353637383132333435363738"
        else:
            ida = self.id_iv.text().strip()
        if len(ida) % 2 != 0:
            ida = ida[0:len(ida)-1]
        sm2_crypt = sm2.CryptSM2(private_key="", public_key=public_key)
        e_hash = sm2_crypt.sm2_get_e(ida, sm2_msg)
        self.e_LE.setText(e_hash.upper())

    def clear_input(self):
        self.privkey.setText("")
        self.pubkx_LE.setText("")
        self.pubky_LE.setText("")
        self.pubkall_LE.setText("")
        self.plaintext.setText("")
        self.plaintext_hex.setText("")
        self.sm3_hash.setText("")
        self.id_iv.setText("")
        self.e_LE.setText("")
        self.signature_value.setText("")
        self.encrypt_result.setText("")
        self.decrypt_result.setText("")

    def sm4_encrypt(self):
        if len(self.privkey.text().strip()) != 32:
            self.Qmsgbox_show("Error", "Key len is not 16 bytes")
            return
        sm4_key = bytes().fromhex(self.privkey.text().strip())

        if self.mode != "ECB":
            if len(self.id_iv.text().strip()) != 32:
                self.Qmsgbox_show("Error", "iv len is not 16 bytes")
                return
            iv = bytes().fromhex(self.id_iv.text().strip())

        crypt_sm4.set_key(sm4_key, SM4_ENCRYPT)
        if self.plaintext_hex.text().strip() == "":
            self.Qmsgbox_show("Error", "Plaintext is null")
            return
        sm4_plaintext = bytes().fromhex(self.plaintext_hex.text().strip())
        self.result_textEdit.append("Plaintext Hex: " + sm4_plaintext.hex().upper())

        if self.pad == True:
            if self.mode == "ECB":
                encrypt_value = crypt_sm4.crypt_ecb(sm4_plaintext)
            elif self.mode == "CBC":
                encrypt_value = crypt_sm4.crypt_cbc(iv, sm4_plaintext)
            else:
                self.Qmsgbox_show("Error", "Please choose mode!");
                return
        else:
            if len(sm4_plaintext) % 16 != 0:
                self.Qmsgbox_show("Error", "Plaintext len is not 16's bytes")
                return
            if self.mode == "ECB":
                encrypt_value = crypt_sm4.crypt_ecb_nopad(sm4_plaintext)
            elif self.mode == "CBC":
                encrypt_value = crypt_sm4.crypt_cbc_nopad(iv, sm4_plaintext)
            else:
                self.Qmsgbox_show("Error", "Please choose mode!");
                return
        self.encrypt_result.setText(encrypt_value.hex().upper())
        self.result_textEdit.append("SM4 Encrypt Result: " + encrypt_value.hex().upper())

    def sm4_decrypt(self):
        #判断密钥是否为16字节
        if len(self.privkey.text().strip()) != 32:
            self.Qmsgbox_show("Error", "Key len is not 16 bytes")
            return
        sm4_key = bytes().fromhex(self.privkey.text().strip())

        #判断是否为ECB模式
        if self.mode != "ECB":
            if len(self.id_iv.text().strip()) != 32:
                QMessageBox.warning(self, "Warning", "iv len is not 16 bytes")
                return
            iv = bytes().fromhex(self.id_iv.text().strip())

        crypt_sm4.set_key(sm4_key, SM4_DECRYPT)

        #对密文长度做16整数倍判断
        encrypt_str = self.encrypt_result.text().strip()
        if encrypt_str == "":
            self.Qmsgbox_show("Error", "Encrypt result is null");
            return
        if self.is_hex_string(encrypt_str) == False:
            self.Qmsgbox_show("Error", "Encrypt result is not hex string");
            return

        if len(encrypt_str) % 32 != 0:
            self.Qmsgbox_show("Error", "Encrypt result is not 16's bytes");
            return
        encrypt_value = bytes().fromhex(encrypt_str)
        self.result_textEdit.append("SM4 Ciphertext: " + encrypt_value.hex().upper())

        #判断是否有填充
        if self.pad == True:
            if self.mode == "ECB":
                decrypt_value = crypt_sm4.crypt_ecb(encrypt_value)
            elif self.mode == "CBC":
                decrypt_value = crypt_sm4.crypt_cbc(iv, encrypt_value)
            else:
                self.Qmsgbox_show("Error", "Please choose mode!");
                return
        else:
            if self.mode == "ECB":
                decrypt_value = crypt_sm4.crypt_ecb_nopad(encrypt_value)
            elif self.mode == "CBC":
                decrypt_value = crypt_sm4.crypt_cbc_nopad(iv, encrypt_value)
            else:
                self.Qmsgbox_show("Error", "Please choose mode!");
                return

        dec_result = bytes(decrypt_value).hex().upper()
        if dec_result != "":
            self.decrypt_result.setText(bytes(decrypt_value).hex().upper())
            self.result_textEdit.append("SM4 Decrypt Result: " + bytes(decrypt_value).hex().upper())
        else:
            #self.decrypt_result.setText("Decrypt failed !!!")
            self.Qmsgbox_show("Error", "SM4 Decrypt failed !!!");
            self.result_textEdit.append("SM4 Decrypt Result: " + "SM4 Decrypt failed !!!")

    def sm3_hash_func(self):
        if self.plaintext_hex.text().strip() == "":
            self.Qmsgbox_show("Error", "Plaintext is null")
            return
        sm3_plaintext = bytes().fromhex(self.plaintext_hex.text().strip())
        self.result_textEdit.append("Msg Hex: " + sm3_plaintext.hex().upper())
        sm3_result = sm3.sm3_hash(func.bytes_to_list(sm3_plaintext))
        self.sm3_hash.setText(sm3_result.upper())
        self.result_textEdit.append("SM3 Hash Result: " + sm3_result.upper())

    def sm2_key_pair_func(self):
        sm2_crypt = sm2.CryptSM2(private_key="", public_key="")
        #产生私钥
        pvk_str = self.privkey.text().strip()
        if pvk_str != "":
            if True != self.is_hex_string(pvk_str):
                self.privkey.setText(pvk_str[0:len(pvk_str) - 1].upper())
                self.Qmsgbox_show("Error", "Please input hex number")
                return
            if len(pvk_str) != 64:
                info = "Length of the private key hex number string is : %d,  error !" % (len(pvk_str))
                self.Qmsgbox_show("Error", info)
                return
            self.privkey.setText(pvk_str.upper())
            prvk_hex = pvk_str
        else:
            prvk_hex = func.random_hex(sm2_crypt.para_len)
            self.privkey.setText(prvk_hex.upper())
        self.result_textEdit.append("Gen Keypair - private key: " + prvk_hex.upper())
        k = int(prvk_hex, 16)
        #计算公钥
        Pubk = sm2_crypt._kg(k, sm2_crypt.ecc_table['g'])
        self.pubkx_LE.setText(Pubk[0:64].upper())
        self.pubky_LE.setText(Pubk[64:len(Pubk)].upper())
        self.result_textEdit.append("Gen Keypair - public key: " + Pubk.upper())

    def sm2_encrypt_func(self):
        public_key = self.pubkall_LE.text().strip()
        if len(public_key) != 128:
            self.Qmsgbox_show("Error", "Public key len is not 64 bytes")
            return

        self.result_textEdit.append("SM2 Encrypt Publickey: " + public_key)
        sm2_crypt = sm2.CryptSM2(private_key="", public_key=public_key)

        if self.plaintext_hex.text().strip() == "":
            self.Qmsgbox_show("Error", "Plaintext is null")
            return
        sm2_plaintext = bytes().fromhex(self.plaintext_hex.text().strip())
        self.result_textEdit.append("Plaintext Hex: " + sm2_plaintext.hex().upper())

        enc_data = sm2_crypt.encrypt(sm2_plaintext)
        self.result_textEdit.append("SM2 Encrypt Result Hex: " + enc_data.hex().upper())
        self.encrypt_result.setText(enc_data.hex().upper())

    def sm2_decrypt_func(self):
        private_key = self.privkey.text().strip()
        if len(private_key) != 64:
            self.Qmsgbox_show("Error", "Private key len is not 32 bytes")
            return
        self.result_textEdit.append("SM2 Decrypt Private_key: " + private_key)
        sm2_crypt = sm2.CryptSM2(private_key=private_key, public_key="")

        encrypt_str = self.encrypt_result.text().strip()
        if len(encrypt_str) <= 192:
            self.Qmsgbox_show("Error", "Encrypt result length should longer than 96 bytes");
            return
        if ((self.is_hex_string(encrypt_str) == False)|(len(encrypt_str)%2 != 0)):
            self.Qmsgbox_show("Error", "Encrypt result is not hex string");
            return
        enc_data = bytes().fromhex(encrypt_str)
        dec_data = sm2_crypt.decrypt(enc_data)
        if dec_data is None:
            self.decrypt_result.setText("")
            self.result_textEdit.append("SM2 Decrypt Result: " + "SM2 Decrypt failed !!!")
            self.Qmsgbox_show("Info", "SM2 Decrypt failed !!!");
        else:
            dec_result = bytes(dec_data).hex().upper()
            self.result_textEdit.append("SM2 Decrypt Result: " + dec_result)
            self.decrypt_result.setText(dec_result)

    def sm2_verify_func(self):
        public_key = self.pubkall_LE.text().strip()
        if len(public_key) != 128:
            self.Qmsgbox_show("Error", "Public key len is not 64 bytes")
            return
        self.result_textEdit.append("SM2 Verify Publickey: " + public_key)
        sm2_crypt = sm2.CryptSM2(private_key="", public_key=public_key)

        e_hash = self.e_LE.text().strip()
        if len(e_hash) != 64:
            self.Qmsgbox_show("Error", "e Hash, len is not 32 bytes")
            return
        if self.is_hex_string(e_hash) == False:
            self.Qmsgbox_show("Error", "e_hash is not hex string");
            return

        self.result_textEdit.append("SM2 Verify e_hash: " + e_hash)

        sign = self.signature_value.text().strip()
        if len(sign) != 128:
            self.Qmsgbox_show("Error", "Signature value, len is not 64 bytes")
            return
        if self.is_hex_string(sign) == False:
            self.Qmsgbox_show("Error", "Sign result is not hex string");
            return
        self.result_textEdit.append("SM2 Verify signature: " + sign.upper())

        verify = sm2_crypt.verify(sign, bytes().fromhex(e_hash))
        if verify == True:
            self.result_textEdit.append("SM2 Verify Result: True")
        else:
            self.result_textEdit.append("SM2 Verify Result: False")
            self.Qmsgbox_show("Info", "Falied to verify signature!!!");

    def sm2_sign_func(self):
        private_key = self.privkey.text().strip()
        if len(private_key) != 64:
            self.Qmsgbox_show("Error", "Private key len is not 32 bytes")
            return
        self.result_textEdit.append("SM2 Sign Privatekey: " + private_key)
        sm2_crypt = sm2.CryptSM2(private_key=private_key, public_key="")

        sm2_msg = self.plaintext_hex.text().strip()
        if sm2_msg != "":
            self.result_textEdit.append("SM2 Sign msg: " + sm2_msg)

        e_hash = self.e_LE.text().strip()
        if len(e_hash) != 64:
            self.Qmsgbox_show("Error", "e Hash, len is not 32 bytes")
            return
        self.result_textEdit.append("SM2 Sign e_hash: " + e_hash)

        random_hex_str = func.random_hex(sm2_crypt.para_len)
        self.result_textEdit.append("SM2 Sign Randnumber: " + random_hex_str.upper())
        sign = sm2_crypt.sign(bytes().fromhex(e_hash), random_hex_str)
        self.result_textEdit.append("SM2 Sign Result: " + sign.upper())
        self.signature_value.setText(sign.upper())

if __name__ == '__main__':
    from PyQt5.QtWidgets import QApplication
    app = QApplication(sys.argv)
    window = cipherToolsUI()
    window.show()
    sys.exit(app.exec())
