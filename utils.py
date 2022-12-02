
import random
import rsa


class Encipher():
    def gen_new_xor_key(self):
        self.xor_key = random.randint(0, 255)

    def __init__(self) -> None:
        self.gen_new_xor_key()
        with open("vpn_server.pub", "r") as file_pub:
            pub_data = file_pub.read()
            self.server_pubkey = rsa.PublicKey.load_pkcs1(pub_data)
        with open("vpn_server", "r") as file_pri:
            pri_data = file_pri.read()
            self.server_prikey = rsa.PrivateKey.load_pkcs1(pri_data)

    def get_encrypted_xor_key(self):
        return rsa.encrypt(self.xor_key.to_bytes(1, byteorder='big'), self.server_pubkey)

    def decrypt_and_update_xor_key(self, encrypted_xor_key):
        xor_key = int.from_bytes(rsa.decrypt(encrypted_xor_key, self.server_prikey), "big")
        self.xor_key = xor_key
        return xor_key

    def XOR_encrypt(self, Post):
        CipheredPost = b''
        Key = self.xor_key
        for byte in Post:
            Cipheredbyte = byte ^ Key
            CipheredPost += bytes((Cipheredbyte,))
        return CipheredPost

    def decrtpt_info(self,info):
        info = rsa.decrypt(info,self.server_prikey)
        return info
