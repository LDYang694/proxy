import socket
import struct
import threading
import os
import json
import re
from utils import Encipher

REFUSED = 0  # Connection denied by this server.


MAX_BUFFER = 4096  # The max size of the post recieved
MAX_CLIENT = 3  # Maximum waiting clients num

VERSION = 19


Username = ''
Passwd = ''


def Construct():
  ULen=len(Username)
  PLen=len(Passwd)
  UName=bytes(Username,encoding='utf-8')
  Pw=bytes(Passwd,encoding='utf-8')
  Post=struct.pack("!BB"+str(ULen)+"sB"+str(PLen)+"s",VERSION,ULen,UName,PLen,Pw)
  return Post


class SendPostTransmitter(threading.Thread):
  '''
  Recieve post from a socket,and transmit it to another.
  '''
  def __init__(self,Sock_1,Sock_2):
    threading.Thread.__init__(self)
    self.AcceptSock=Sock_1
    self.SendSock=Sock_2
  def run(self):
    while True:
      try:
        Post=self.AcceptSock.recv(MAX_BUFFER)
         # SafePost=Encipher(Post)
        self.SendSock.send(encipher.XOR_encrypt(Post))
      except BrokenPipeError:
        pass
      except ConnectionResetError:
        pass


class RecvPostTransmitter(threading.Thread):
  '''
  Recieve post from a socket,and transmit it to another.
  '''
  def __init__(self,Sock_1,Sock_2):
    threading.Thread.__init__(self)
    self.AcceptSock=Sock_1
    self.SendSock=Sock_2
  def run(self):
    while True:
      try:
        Post=self.AcceptSock.recv(MAX_BUFFER)
        self.SendSock.send(encipher.XOR_encrypt(Post))
      except BrokenPipeError:
        pass
      except ConnectionResetError:
        pass


class TCPHandler(threading.Thread):
  '''
  Communicate with one single Client.
  '''
  def __init__(self,ClientSock,RemoteAddress,RemotePort):
    threading.Thread.__init__(self)
    self.ClientSock=ClientSock
    try:
      self.RemoteSock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
      self.RemoteSock.connect((RemoteAddress,RemotePort))
    except:
      print('Some error occured.')

  def run(self):
    #step0:向server发送握手请求
    handshake = struct.pack("!BB",VERSION,0)
    self.RemoteSock.send(handshake)
    handshake_rec = self.RemoteSock.recv(MAX_BUFFER)
    version,ask_pub_key,need_login=struct.unpack("!BBB",handshake_rec)
   
     # step1: 将xor_key用proxy.pub加密后发送给proxy
    encipher.gen_new_xor_key()
    self.RemoteSock.send(
      struct.pack(
        '!64s',
        encipher.get_encrypted_xor_key()
      )
    )
    #step2:构建登录包 发送给proxy 并接收验证
    if need_login==1:
      Request=Construct()
      self.RemoteSock.send(encipher.encrypt_info(Request))
      Answer=self.RemoteSock.recv(MAX_BUFFER)
      version,answer = struct.unpack("!BB",Answer)
      if answer != 0:
        print('Invalid Username or wrong password.')
        os.sys.exit()
    else:
      pass
    print("login success!")
     

    # step3：接受browser的第一个包，告知proxy IP和port
    try:
      Post = self.ClientSock.recv(MAX_BUFFER)
      addresss = [int(r) for r in re.search(r'Host: ([0-9]+).([0-9]+).([0-9]+).([0-9]+)', str(Post, encoding='utf-8')).groups()]
      port = 80
      print("Get Http Pack to {}:{}".format(addresss,port))
    except Exception:
      print("Not Http Pack,can not handler")
      return 
    self.RemoteSock.send(encipher.XOR_encrypt(
      struct.pack(
        '!B' + str(4) + 'BH',VERSION,
        *addresss, port
      )
    ))
    # 接受proxy的确认包
    confirm = encipher.XOR_encrypt(self.RemoteSock.recv(MAX_BUFFER))
    version,status,rawaddress,port = struct.unpack("!BB"+str(4)+"sH",confirm)
    if status==REFUSED:
      #
      print("REFUSED!!!")
      os.sys.exit()
    
    # step4：将browser的第一个包发送给proxy
    self.RemoteSock.send(encipher.XOR_encrypt(Post))
    # step5：开始持续发送和接受包
    SendThread = SendPostTransmitter(self.ClientSock, self.RemoteSock)
    AcceptThread = RecvPostTransmitter(self.RemoteSock, self.ClientSock)
    SendThread.start()
    AcceptThread.start()
  
      


if __name__ == '__main__':
  encipher = Encipher()
  ServerSock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
  print('Welcome !\n')
  try:
    ConfigFile=open("./ClientConfig.json","r")
    Config=json.load(ConfigFile)
  except:
    print('Cannot open the config file.')
    print('Please input config information yourself.\n')
    print('Please input the IP address and port you want to bind with.')
    try:
      Address=input('IP address:')
      Port=input('Port:')
    except KeyboardInterrupt:
      print('\n\nbye bye.\n')
      os.sys.exit()
    print('Please input the IP address and port of the proxy server.')
    try:
      RemoteAddress=input('IP address:')
      RemotePort=input('Port:')
    except KeyboardInterrupt:
      print('\n\nbye bye.\n')
      os.sys.exit()
  else:
    try:
      Address=Config['LocalIP']
      Port=Config['LocalPort']
      RemoteAddress=Config['RemoteIP']
      RemotePort=Config['RemotePort']
      Username=Config['Username']
      Passwd=Config['Password']


    except KeyError:
      print('Config information error. Please check your config file.')
      os.sys.exit()

  print("\nWaiting for connection ...\n")
  try:
    ServerSock.bind((Address,int(Port)))
    ServerSock.listen(MAX_CLIENT)
    while True:
      CliSock,CliAddr=ServerSock.accept()
      Thread=TCPHandler(CliSock,RemoteAddress,int(RemotePort))
      Thread.start()
  except OSError:
    print("Error: Address already in use. Please use another port.")
    os.sys.exit()
  except KeyboardInterrupt:
    print('\n\nbye bye.\n')
    os.sys.exit()
  finally:
    ServerSock.close()


  
  
  