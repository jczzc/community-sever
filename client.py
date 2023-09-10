import os
import rsa
import pickle
import json
import time
import socket
import struct
import hashlib
import tqdm
import copy
import maskpass


def main():
  print('enter your username and password')
  print('if you are new member,just continue with no input')
  con=True
  if input('IP(IPv6/IPv4):')=='IPv6':
    ip=socket.AF_INET6
    pro=socket.SOCK_STREAM
  else:
    ip=socket.AF_INET
    pro=socket.SOCK_STREAM
  with open('disposition.json','bw') as f:
    pickle.dump([ip,pro],f)
  ser_name=input('sever_name:')
  ser_port=input('sever_port:')
  with open('sever.json','wb') as se:
    pickle.dump([ser_name,int(ser_port)],se)
  while con:
    usrname=input('usrname:').encode()
    name=usrname.decode()
    if usrname==b'':
      con1=True
      while con1:
        print('please enter your usrname')
        usrname=input('usrname:').encode()
        s=socket.socket(ip,pro)
        s.connect((ser_name,int(ser_port)))
        cont='name_test'.encode()
        lenth=struct.pack('L',len(cont))
        s.send(lenth)
        s.send(cont)
        lenth=struct.pack('L',len(usrname))
        s.send(lenth)
        s.send(usrname)
        command=s.recv(1).decode()
        #print(command)
        if command=='F':
          con1=False
        else:
          print('usr_name_already_exists')
      print('please_enter_your_password')
      password=maskpass.askpass(prompt='password:',mask='.').encode()
      repeat_password=maskpass.askpass(prompt='password:',mask='.').encode()
      if password!=repeat_password:
          print('The password is inconsistent with the verification')
          continue
      key_password=hashlib.sha512(password).hexdigest().encode()
      s=socket.socket(ip,pro)
      s.connect((ser_name,int(ser_port)))
      cont='sign_up'.encode()
      lenth=struct.pack('L',len(cont))
      s.send(lenth)
      s.send(cont)
      sever_encoded_public_key_len=struct.unpack('L',s.recv(4))[0]
      sever_encoded_public_key=s.recv(sever_encoded_public_key_len)
      sever_public_key=pickle.loads(sever_encoded_public_key)
      encrypted_usrname=rsa.encrypt(usrname,sever_public_key)
      encrypted_key_password=rsa.encrypt(key_password,sever_public_key)
      lenth=struct.pack('L',len(encrypted_usrname))
      s.send(lenth)
      s.send(encrypted_usrname)
      lenth=struct.pack('L',len(encrypted_key_password))
      s.send(lenth)
      s.send(encrypted_key_password)
      break
    password=maskpass.askpass(prompt='password:',mask='●').encode()
    key_password=hashlib.sha512(password).hexdigest().encode()
    s=socket.socket(ip,pro)
    s.connect((ser_name,int(ser_port)))
    cont='login_in'.encode()
    lenth=struct.pack('L',len(cont))
    s.send(lenth)
    s.send(cont)
    sever_encoded_public_key_len=struct.unpack('L',s.recv(4))[0]
    sever_encoded_public_key=s.recv(sever_encoded_public_key_len)
    sever_public_key=pickle.loads(sever_encoded_public_key)
    encrypted_usrname=rsa.encrypt(usrname,sever_public_key)
    encrypted_key_password=rsa.encrypt(key_password,sever_public_key)
    lenth=struct.pack('L',len(encrypted_usrname))
    s.send(lenth)
    s.send(encrypted_usrname)
    lenth=struct.pack('L',len(encrypted_key_password))
    s.send(lenth)
    s.send(encrypted_key_password)
    cmd=s.recv(1).decode()
    if cmd=='T':
      con=False
    else:print('account error')
  print('login_end')
  while True:
    command=input('command:')
    if command=='send_file':
      file_path=input('file_path:')+os.sep
      file_name=input('file_name:')
      file_path+=file_name
      if not os.path.exists(file_path):
        print('no such file')
        continue
      file_size=os.path.getsize(file_path)
      size=piece_size=1024*150
      num=piece_num=file_size//piece_size
      if file_size%piece_size>0:
        #piece_num+=1
        end_size=file_size%piece_size
      else:
        piece_num-=1
        num-=1
        end_size=piece_size
      end_size=struct.pack('L',end_size)
      piece_num=struct.pack('L',piece_num)
      piece_size=struct.pack('L',piece_size)
      s=socket.socket(ip,pro)
      s.connect((ser_name,int(ser_port)))
      cont='file_send'.encode()
      lenth=struct.pack('L',len(cont))
      s.send(lenth)
      s.send(cont)
      sever_encoded_public_key_len=struct.unpack('L',s.recv(4))[0]
      sever_encoded_public_key=s.recv(sever_encoded_public_key_len)
      sever_public_key=pickle.loads(sever_encoded_public_key)
      encrypted_usrname=rsa.encrypt(usrname,sever_public_key)
      encrypted_key_password=rsa.encrypt(key_password,sever_public_key)
      lenth=struct.pack('L',len(encrypted_usrname))
      s.send(lenth)
      s.send(encrypted_usrname)
      lenth=struct.pack('L',len(encrypted_key_password))
      s.send(lenth)
      s.send(encrypted_key_password)
      cmd=s.recv(1).decode()
      if cmd=='T':
        lenth=struct.pack('L',len(file_name.encode()))
        s.send(lenth)
        s.send(file_name.encode())
        s.send(piece_num)
        with open(file_path,'br') as f:
          for i in tqdm.tqdm(range(num)):
            piece=f.read(size)
            s.send(piece_size)
            time.sleep(0.02)
            s.send(piece)
            s.recv(1)
            #print(i)
          piece=f.read(size)
          s.send(end_size)
          s.send(piece)
          s.recv(1)
          print('end')
      else:print('account error')
    elif command=='get_file':
      author=input('author:')
      file=input('file_name:')
      save_path=input('save_path:')
      if not os.path.exists(save_path):
        print('no such path')
        continue
      author_name=author.encode()
      file_name=file.encode()
      s=socket.socket(ip,pro)
      s.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,False)
      s.connect((ser_name,int(ser_port)))
      cont='file_get'.encode()
      lenth=struct.pack('L',len(cont))
      s.send(lenth)
      s.send(cont)
      sever_encoded_public_key_len=struct.unpack('L',s.recv(4))[0]
      sever_encoded_public_key=s.recv(sever_encoded_public_key_len)
      sever_public_key=pickle.loads(sever_encoded_public_key)
      encrypted_usrname=rsa.encrypt(usrname,sever_public_key)
      encrypted_key_password=rsa.encrypt(key_password,sever_public_key)
      lenth=struct.pack('L',len(encrypted_usrname))
      s.send(lenth)
      s.send(encrypted_usrname)
      lenth=struct.pack('L',len(encrypted_key_password))
      s.send(lenth)
      s.send(encrypted_key_password)
      cmd=s.recv(1).decode()
      if cmd=='T':
        lenth=struct.pack('L',len(author_name))
        s.send(lenth)
        s.send(author_name)
        lenth=struct.pack('L',len(file_name))
        s.send(lenth)
        s.send(file_name)
        cmd=s.recv(1).decode()
        if cmd=='T':
          file_piece_num=struct.unpack('L',s.recv(4))[0]
          print(file_piece_num,'pieces in all')
          with open(save_path+os.sep+file,'bw') as f:
            cont=0
            for i in tqdm.tqdm(range(file_piece_num+1)):
              #lenth=0
              lenth=copy.deepcopy(struct.unpack('Q',s.recv(8))[0])
              #print(cont,'/',file_piece_num+1,'|',lenth)
              _=lenth
              piece=s.recv(lenth)
              f.write(piece)
              #f.flush()
              s.send('V'.encode())
              #print(i)
              #os.system('cls')
              cont+=1
            f.flush()
            f.close()
        else:
          print('no such file/author')
      else:print('account error')
    elif command=='chat':
      with open('account.json','w') as f:
        json.dump([name,key_password.decode()],f)
      if os.path.exists('test.sign'):
        os.system('start client_helper.py')
      else:
        os.system('start client_helper.exe')
      com=True
      while com:
        message=input('>>')
        if message=='exit':
          break
        message=[name,message]
        message=pickle.dumps(message)
        s=socket.socket(ip,pro)
        s.connect((ser_name,int(ser_port)))
        cont='send_message'.encode()
        lenth=struct.pack('L',len(cont))
        s.send(lenth)
        s.send(cont)
        sever_encoded_public_key_len=struct.unpack('L',s.recv(4))[0]
        sever_encoded_public_key=s.recv(sever_encoded_public_key_len)
        sever_public_key=pickle.loads(sever_encoded_public_key)
        encrypted_usrname=rsa.encrypt(usrname,sever_public_key)
        encrypted_key_password=rsa.encrypt(key_password,sever_public_key)
        lenth=struct.pack('L',len(encrypted_usrname))
        s.send(lenth)
        s.send(encrypted_usrname)
        lenth=struct.pack('L',len(encrypted_key_password))
        s.send(lenth)
        s.send(encrypted_key_password)
        control=s.recv(1).decode()
        if control=='T':
          sever_encoded_public_key_len=struct.unpack('L',s.recv(4))[0]
          sever_encoded_public_key=s.recv(sever_encoded_public_key_len)
          sever_public_key=pickle.loads(sever_encoded_public_key)
          message=rsa.encrypt(message,sever_public_key)
          message_len=struct.pack('L',len(message))
          s.send(message_len)
          s.send(message)
        else:
          print('account error')
      s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
      s.sendto('end'.encode(),('127.0.0.1',3072))
      s=socket.socket(ip,pro)
      s.connect((ser_name,int(ser_port)))
      cont='chat_exit'.encode()
      lenth=struct.pack('L',len(cont))
      s.send(lenth)
      s.send(cont)
      sever_encoded_public_key_len=struct.unpack('L',s.recv(4))[0]
      sever_encoded_public_key=s.recv(sever_encoded_public_key_len)
      sever_public_key=pickle.loads(sever_encoded_public_key)
      encrypted_usrname=rsa.encrypt(usrname,sever_public_key)
      encrypted_key_password=rsa.encrypt(key_password,sever_public_key)
      lenth=struct.pack('L',len(encrypted_usrname))
      s.send(lenth)
      s.send(encrypted_usrname)
      lenth=struct.pack('L',len(encrypted_key_password))
      s.send(lenth)
      s.send(encrypted_key_password)
      print("sever's reply") 
      print(s.recv(1).decode())
      print('exited room')
    elif command=='exit':
      break
    elif command=='cls':
      os.system('cls')
    elif command=='change_password':
      password=maskpass.askpass(prompt='password:',mask='.').encode()
      repeat_password=maskpass.askpass(prompt='password:',mask='.').encode()
      if password!=repeat_password:
        print('The password is inconsistent with the verification')
        continue
      new_key_password=hashlib.sha512(password).hexdigest().encode()
      s=socket.socket(ip,pro)
      s.connect((ser_name,int(ser_port)))
      cont='change_password'.encode()
      lenth=struct.pack('L',len(cont))
      s.send(lenth)
      s.send(cont)
      sever_encoded_public_key_len=struct.unpack('L',s.recv(4))[0]
      sever_encoded_public_key=s.recv(sever_encoded_public_key_len)
      sever_public_key=pickle.loads(sever_encoded_public_key)
      encrypted_usrname=rsa.encrypt(usrname,sever_public_key)
      encrypted_key_password=rsa.encrypt(key_password,sever_public_key)
      new_encrypted_key_password=rsa.encrypt(new_key_password,sever_public_key)
      lenth=struct.pack('L',len(encrypted_usrname))
      s.send(lenth)
      s.send(encrypted_usrname)
      lenth=struct.pack('L',len(encrypted_key_password))
      s.send(lenth)
      s.send(encrypted_key_password)
      cmd=s.recv(1).decode()
      if cmd=='T':
        lenth=struct.pack('L',len(new_encrypted_key_password))
        s.send(lenth)
        s.send(new_encrypted_key_password)
