import rsa


def generate_and_save_key(filename):
    (pubkey, privkey) = rsa.newkeys(512)  # 创建公钥和私钥，512为设定你加密字符串的最大可支持加密长度为512位=64字节，你也可以按需设置任意长度，越长加密越慢，越短越快
    # 将公钥和私钥以pem编码格式保存
    pub = pubkey.save_pkcs1()
    pri = privkey.save_pkcs1()
    # print(f"公钥初始的值为：{pubkey}，以pem格式的保存后的数据为：{pub}")
    # print(f"私钥初始的值为：{privkey} \n 以pem格式的保存后的私钥数据为：{pri}")
    # 将公钥保存到文件 ,将字节写入文件需要加上decode（'utf-8'），python3新增
    with open("%s.pub" % filename, 'w+') as file:  # public.pub，保存的文件名，可更改路径，这里保存在当前路径下
        file.write(pub.decode("utf-8"))
    # 将私钥保存到文件
    with open("%s" % filename, 'w+') as file:
        file.write(pri.decode('utf-8'))

def read_key(filename):
    # 取出公钥
    with open("%s.pub" % filename, "r") as file_pub:
        # 从文件中读出数据
        pub_data = file_pub.read()
        # 将读出数据通过PublicKey.load_pkcs1()转换为公钥
        pubkey = rsa.PublicKey.load_pkcs1(pub_data)
    with open("%s" % filename, "r") as file_pub:
        # 从文件中读出数据
        pub_data = file_pub.read()
        # 将读出数据通过PublicKey.load_pkcs1()转换为公钥
        prikey = rsa.PrivateKey.load_pkcs1(pub_data)
    return pubkey, prikey
    # # 取出私钥
    # with open("private.pub", "r") as file_pri:
    #     pri_data = file_pri.read()
    #     # 将读出数据通过PrivateKey.load_pkcs1()转换为私钥
    #     prikey = rsa.PrivateKey.load_pkcs1(pri_data)


# generate_and_save_key("vpn_client")
# generate_and_save_key("vpn_server")
pub, pri = read_key("vpn_server")
en = rsa.encrypt(bytes("hello", encoding='utf-8'), pri)
print(rsa.decrypt(en, pri).decode('utf-8'))

