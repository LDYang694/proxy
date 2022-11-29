import socket
import struct
import threading
import os
import json
import re
from utils import Encipher

# Define 4 status of the HandShake period.
REFUSED = 0  # Connection denied by this server.
TCP = 1  # Build TCP connection with the remoteserver
UDP = 2  # Build UDP association with the remoteserver
BIND = 3  # Reversed Link (Not implemented yet)

MAX_BUFFER = 4096  # The max size of the post recieved
MAX_CLIENT = 3  # Maximum waiting clients num

Method = 0  # Authentacation method.
# 0 represents no authentacation
# 2 represents Username-Password
Username = ''
Passwd = ''


def Construct():
  ULen=len(Username)
  PLen=len(Passwd)
  UName=bytes(Username,encoding='utf-8')
  Pw=bytes(Passwd,encoding='utf-8')
  Post=struct.pack("!BB"+str(ULen)+"sB"+str(PLen)+"s",0x05,ULen,UName,PLen,Pw)
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
         # SafePost=Encipher(Post)
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
     # step1: 将xor_key用proxy.pub加密后发送给proxy
    encipher.gen_new_xor_key()
    self.RemoteSock.send(
      struct.pack(
        '!64s',
        encipher.get_encrypted_xor_key()
      )
    )
     # TODO encrypt
    if Method == 2:
      Request=Construct()
      self.RemoteSock.send(Request)
      Answer=self.RemoteSock.recv(MAX_BUFFER)
      if Answer != b'\x05\x00':
        print('Invalid Username or wrong password.')
        os.sys.exit()

     # step2：接受browser的第一个包，告知proxy IP和port
    Post = self.ClientSock.recv(MAX_BUFFER)
    addresss = [int(r) for r in re.search(r'Host: ([0-9]+).([0-9]+).([0-9]+).([0-9]+)', str(Post, encoding='utf-8')).groups()]
    port = 80
    self.RemoteSock.send(encipher.XOR_encrypt(
      struct.pack(
        '!' + str(4) + 'BH',
        *addresss, port
      )
    ))
     # 接受proxy的确认包
    encipher.XOR_encrypt(self.RemoteSock.recv(MAX_BUFFER))
     # step3：将browser的第一个包发送给proxy
    self.RemoteSock.send(encipher.XOR_encrypt(Post))
     # step4：开始持续发送和接受包
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
      Method=Config['Method']
      RemoteAddress=Config['RemoteIP']
      RemotePort=Config['RemotePort']
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


  
  
  