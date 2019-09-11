import base64
import binascii
from gmssl import sm2, func


if __name__ == '__main__':
    private_key = '6C5B1CC156AE465EF26973E0E01C466157B81521D448D4F6DE6671A697FCB1B6'
    public_key = '27AE9564D854B5585BF1662225B9AF566A3877F389AB64B085D52ABE02D988593912F8185ED47FC41574FB6BDB5EE118643CA11FCF655E3336B3E6C36A8F1645'

    sm2_crypt = sm2.CryptSM2(
        public_key=public_key, private_key=private_key)
    data = b"1234567812345678"
    enc_data = sm2_crypt.encrypt(data)
    #print("enc_data:%s" % enc_data)
    #print("enc_data_base64:%s" % base64.b64encode(bytes.fromhex(enc_data)))
    dec_data = sm2_crypt.decrypt(enc_data)
    print(b"dec_data:%s" % dec_data)
    assert data == dec_data

    ida = "C8A427891024E0F839875DC5435C4A20CA5BC75A8CE30B3B26A74D0E1EA4E4E0"
    msg = "2656AD299F2BADE95D38F7F7AA2AD096"
    sm2_crypt.sm2_get_z(ida)
    sm2_crypt.sm2_get_e(ida,msg)
    print("-----------------test sign and verify---------------")
    random_hex_str = func.random_hex(sm2_crypt.para_len)
    print("random_hex_str: ", random_hex_str)
    sign = sm2_crypt.sign(data, random_hex_str)
    print('sign:%s' % sign)
    verify = sm2_crypt.verify(sign, data)
    print('verify:%s' % verify)
    assert verify
