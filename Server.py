import socket
import struct
import threading
import os
import json
from utils import Encipher

# Define 4 status of the HandShake period.
REFUSED=0 # Connection denied by this server.
# TCP=1 # Build TCP connection with the remoteserver
# UDP=2 # Build UDP association with the remoteserver
# BIND=3 # Reversed Link (Not implemented yet)
ACCESS =1
MAX_BUFFER=4096 # The max size of the post recieved
MAX_CLIENT=3 # Maximum waiting clients num
VERSION = 19
NEED_LOGIN=1
Method=0 # Authentacation method.
# 0 represents no authentacation
# 2 represents Username-Password
Username=''
Passwd=''


class PostTransmitter(threading.Thread):
    '''
    Recieve post from a socket,and transmit it to another.
    '''
    def __init__(self, Sock_1, Sock_2):
        threading.Thread.__init__(self)
        self.AcceptSock = Sock_1
        self.SendSock = Sock_2

    def run(self):
        while True:
            try:
                Post = self.AcceptSock.recv(MAX_BUFFER)
                # SafePost=Encipher(Post)
                self.SendSock.send(encipher.XOR_encrypt(Post))
            except BrokenPipeError:
                pass
            except ConnectionResetError:
                pass





def HandShake(Post):
    '''
    Handle the handshake period of server and client.
    '''
    # +-----+----------+----------+
    # | VER | NMETHODS | METHODS    |
    # +-----+----------+----------+
    # |    1    |        1         |    1~255     |
    # +-----+----------+----------+
    Version, MethodNum = struct.unpack('!BB', Post[:2])
    Post=Post[2:]
    Format='!'
    for i in range(0,MethodNum):
        Format+='B'
    Methods = struct.unpack(Format,Post)
    if 0 in Methods:
        AcceptMethod=0x00 
    else:
        AcceptMethod=0xff
        # If client doesn't support no authentacation mode, refuse its request.
    Answer=struct.pack('!BB',Version,AcceptMethod)
    return Answer


def Verify(Post):
    Version,ULen=struct.unpack('!BB',Post[:2])
    assert Version == VERSION
    Uname,PLen=struct.unpack('!'+str(ULen)+"sB",Post[2:3+ULen])
    Pw,=struct.unpack('!'+str(PLen)+'s',Post[3+ULen:])
    if Uname == bytes(Username,encoding='utf-8') and Pw == bytes(Passwd,encoding='utf-8'):
        reply=0x00
    else:
        reply=0xff
    Answer=struct.pack('!BB',Version,reply)
    return Answer


# def Connect(Post):
#     '''
#     The second handshake with client.
#     '''
    
#     PostInfo={}
#     if Post != b'':
#         PostInfo['Version'],PostInfo['Command'],PostInfo['RSV'],PostInfo['AddrType']\
#         = struct.unpack('!BBBB',Post[:4])

#     # AddressType:
#     # 0x01 - IPv4
#     # 0x03 - DomainName (not supported)
#     # 0x04 - IPv6
#     if PostInfo['AddrType'] == 0x01:
#         Length=4
#         # Parse RemoteServer's address by AddrType
#         Format='!'+str(Length)+'sH'
#         RawAddress,PostInfo['RemotePort']=struct.unpack(Format,Post[4:])
#         PostInfo['RemoteAddress']=socket.inet_ntoa(RawAddress)
#     elif PostInfo['AddrType'] == 0x04:
#         Length=16
#         # Parse RemoteServer's address by AddrType
#         Format='!'+str(Length)+'sH'
#         RawAddress,PostInfo['RemotePort']=struct.unpack(Format,Post[4:])
#         PostInfo['RemoteAddress']=socket.inet_ntoa(RawAddress)
#     elif PostInfo['AddrType'] == 0x03:
#         Length,=struct.unpack('!B',Post[4:5])
#         url,PostInfo['RemotePort']=struct.unpack('!'+str(Length)+'sH',Post[5:])
#         PostInfo['Length']=Length
#         PostInfo['url']=url
#         print('Connecting '+str(url,encoding='utf-8'))
#         PostInfo['RemoteAddress']=socket.gethostbyname(url)
#     else:
#         print('Error: Wrong address type.')
#         PostInfo['REP']=0x08
#         return (PostInfo,REFUSED)

#     # Respond to Client's Command.
#     if PostInfo['Command'] == 0x01:
#         PostInfo['REP']=0x00
#         return (PostInfo,TCP)
#     elif PostInfo['Command'] == 0x02:
#         PostInfo['REP']=0x08
#         return (PostInfo,BIND)
#     elif PostInfo['Command'] == 0x03:
#         PostInfo['REP']=0x00
#         return (PostInfo,UDP)
#     else:
#         PostInfo['REP']=0x02
#         return (PostInfo,REFUSED)


def MyConnect(Post):
    '''
    The second handshake with client.
    '''
    PostInfo = {}
    if Post != b'':
        Format = '!' + str(4) + 'sH'
        RawAddress, PostInfo['RemotePort'] = struct.unpack(Format, Post)
        PostInfo['RemoteAddress'] = socket.inet_ntoa(RawAddress)
        return (PostInfo, ACCESS)
    else:
        return (PostInfo, REFUSED)


class TCPHandler(threading.Thread):
    '''
    Communicate with one single Client.
    '''
    def __init__(self, ClientSock):
        threading.Thread.__init__(self)
        self.ClientSock = ClientSock

    def run(self):
        #step0 :获取握手请求
        handshake=self.ClientSock.recv(MAX_BUFFER)
        version,ask_pub_key = struct.unpack("!BB",handshake)
        try:
          assert version==VERSION
          assert ask_pub_key == 0
        except AssertionError:

          pass
        finally:
          handshake_rec = struct.pack("!BBB",version,ask_pub_key,NEED_LOGIN)
          self.ClientSock.send(handshake_rec)
          pass

        # step1: 获取client的xor_key
        Post = self.ClientSock.recv(MAX_BUFFER)
        encrypted_xor_key = struct.unpack(
          '!64s',
          Post
        )[0]
        encipher.decrypt_and_update_xor_key(encrypted_xor_key)

       
        #step2 登录认证
        Post=self.ClientSock.recv(MAX_BUFFER)
        Post = encipher.decrtpt_info(Post)
        self.ClientSock.send(Verify(Post))

        # step3：接受包含IP和port的包 并判断
        Post = encipher.XOR_encrypt(self.ClientSock.recv(MAX_BUFFER))
        PostInfo, Status = MyConnect(Post)
        if Status==REFUSED:
            print('Request refused.')
            Answer=struct.pack('!BB'+str(4)+'sH',\
            PostInfo['Version'],REFUSED,socket.inet_ntoa(PostInfo['RemoteAddress']),PostInfo['RemotePort'])
            self.ClientSock.send(encipher.XOR_encrypt(Answer))
            self.ClientSock.close()
            return
        else:
            Answer = struct.pack('!BB'+str(4)+'sH',\
            PostInfo['Version'],REFUSED,socket.inet_ntoa(PostInfo['RemoteAddress']),PostInfo['RemotePort'])
            self.ClientSock.send(encipher.XOR_encrypt(Answer))
            try:
                RemoteSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                RemoteSock.connect((PostInfo['RemoteAddress'], PostInfo['RemotePort']))
            except ConnectionRefusedError:
                print('Error: Connection refused.')
                RemoteSock.close()
            else:
                # step4：开始持续发送和接受包
                SendThread = PostTransmitter(self.ClientSock, RemoteSock)
                AcceptThread = PostTransmitter(RemoteSock, self.ClientSock)
                SendThread.start()
                AcceptThread.start()
        # 第二次建立连接
        # RawPost=self.ClientSock.recv(MAX_BUFFER)
        # Post=Encipher(RawPost)
        

        # # Judge Status
        # if Status == REFUSED:
        #     # assert(False)
        #     # If server refuses client's request,send the answer and close the socket.
           
        # else:
        #     # Connect or associate with the remote server.
        #     if Status == ACCESS:
                
           


if __name__ == '__main__':
    encipher = Encipher()
    ServerSock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    print('Welcome !\n')
    try:
        ConfigFile=open("./ServerConfig.json","r")
        Config=json.load(ConfigFile)
    except:
        print('Cannot open the config file.')
        print('Please input config information yourself.\n')
        print('Please input the port you want to bind with.')
        try:
            Address='0.0.0.0'
            Port=input('Port:')
        except KeyboardInterrupt:
            print('\n\nbye bye.\n')
            os.sys.exit()
    else:
        try:
            Address=Config['BindIP']
            Port=Config['BindPort']
            Method=Config['Method']
            if Method == 2:
                Username=Config['Username']
                Passwd=Config['Password']
            elif Method == 0:
                pass
            else:
                print("This method is not supported.")
                os.sys.exit()
        except KeyError:
            print('Config information error. Please check your config file.')
            os.sys.exit()
    print("\nWaiting for connection ...\n")
    try:
        ServerSock.bind((Address,int(Port)))
        ServerSock.listen(MAX_CLIENT)
        while True:
            CliSock,CliAddr=ServerSock.accept()
            Thread=TCPHandler(CliSock)
            Thread.start()
    except OSError:
        print("Error: Address already in use. Please use another port.")
        os.sys.exit()
    except KeyboardInterrupt:
        print('\n\nbye bye.\n')
        os.sys.exit()
    finally:
        ServerSock.close()


    
    
    
