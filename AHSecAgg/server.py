from utils import *
from init import *
import json
import numpy as np
import socket
import threading
import time

class server(object):
    def __init__(self, port: int):
        self.port = port
        self.allnode = dict()
        self.pubkeys = dict()
        self.u1 = []
        
        self.shares = dict()
        self.u2 = []
        
        self.u3 = []
        self.maskMsg = dict()
        
        self.u4 = []
        self.unmaskMsg = dict()
        t_receive=threading.Thread(target=self.receiveAlways,args=())
        t_receive.start() 
        
        # self.pubkeysSendFlag = 0
        # self.sharesSendFlag = 0
        # self.maskMsgSendFlag = 0
        
        self.result = [0 for i in range(dimension)]
    def receiveAlways(self):
        '''
        msg_type:
        0：退出接收
        1：公钥消息
        2：份额消息
        3：掩码消息
        4：恢复份额消息
        '''
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((localhost, self.port))
        s.listen(100)
        self.pubkeys.clear()
        self.u1.clear()
        self.shares.clear()
        self.u2.clear()
        self.maskMsg.clear()
        self.u3.clear()
        self.unmaskMsg.clear()
        self.u4.clear()
        while(True):
            sock, addr = s.accept()
            data=sock.recv(max(65536, 1024 * len(self.u1)))#缓冲区
            buffer = json.loads(data)  # 设置缓冲器，指定一次接收的数据量
            print("收到的消息为：")
            
            print(buffer)
            #print("\n")
            sock.close()
            if(buffer[1] == 0):
                break
            elif(buffer[1] == 1):
                
                self.pubkeys[buffer[2]['id']] = dict()
                #self.pubkeys[buffer[2]['id']]['maskKey'] = buffer[2]['maskKey']
                self.pubkeys[buffer[2]['id']]['aecKey'] = buffer[2]['aecKey']
                self.u1.append(buffer[2]['id'])
                self.allnode[buffer[2]['id']] = buffer[2]['port']
            elif(buffer[1] == 2):
                self.u2.append(buffer[2]['from_id'])
                self.shares[buffer[2]['from_id']] = buffer[2]['msg']
            elif(buffer[1] == 3):
                self.u3.append(buffer[2]['id'])
                self.maskMsg[buffer[2]['id']] = buffer[2]['yu']
            elif(buffer[1] == 4):
                self.u4.append(buffer[2]['from_id'])
                self.unmaskMsg[buffer[2]['from_id']] = buffer[2]['msg']
                
                
    def exitReceive(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((localhost, self.port))
        message=[self.port,0]
        msg_send=json.dumps(message)
        s.send(msg_send.encode())
        s.close()

    def broadcasttoClients(self, idlist, send_message, msg_type):
        #self.local_msg.append(message)
        '''
        msg_type:
        1：公钥
        2：私钥份额
        3：maskMsg
        '''
        for idnum in idlist:
            #print(idnum)
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((localhost, self.allnode[idnum]))
                message=[self.port, msg_type, send_message]
                msg_send=json.dumps(message)
                s.send(msg_send.encode())
                s.close()
            except:
                pass
    
    def genPubkeysMsg(self) -> str:
        send = {'idlist': self.u1, 'pubkeys': self.pubkeys}
        #send = json.dumps(send)
        return send
    
    def genSharesMsg(self) -> str:
        send = {'idlist': self.u2, 'msg': self.shares}
        #send = json.dumps(send)
        return send
    
    def genMaskMsg(self) -> str:
        send = {'idlist': self.u3, 'msg': self.maskMsg}
        #send = json.dumps(send)
        return send  
    
    def recoverMsg(self):
        nodeNum = len(self.u1)
        thres = nodeNum // 3 + 1
        #symbol = dict()
        #print(self.unmaskMsg)
        indexformask = []
        sharesformask = []
        for i in self.unmaskMsg:
            indexformask.append(i)
            sharesformask.append(self.unmaskMsg[i])
        #print(self.maskMsg)
        for i in self.maskMsg:
            tmp = StrToNdarry(self.maskMsg[i]).tolist()
            for j in range(len(tmp)):
                self.result[j] = (self.result[j] + tmp[j]) % DHp
        secret = recon(thres,indexformask,sharesformask,DHp) % DHp
        #prg = PRG(secret)
        #print(secret)
        #for i in range(len(self.result)):
            #self.result[i] -= prg.genRandint()
        #print(secret)
        #print(self.result)
        tmp = (r * secret) % DHp
        for i in range(len(self.result)):
            #yu[i] += prg.genRandint()
            self.result[i] = (self.result[i] - tmp) % DHp
            tmp = (tmp * r) % DHp
    
    def startRound(self,timewait):
        time.sleep(timewait)
        self.broadcasttoClients(self.u1, self.genPubkeysMsg(), 1)
        print(len(self.u1),self.u1)
        time.sleep(timewait)
        self.broadcasttoClients(self.u2, self.genSharesMsg(), 2)
        print(len(self.u2),self.u2)
        time.sleep(timewait)
        self.broadcasttoClients(self.u3, self.genMaskMsg(), 3)
        print(len(self.u3),self.u3)
        time.sleep(timewait)
        self.recoverMsg()
        print(len(self.u4),self.u4)
        self.exitReceive()
        print("聚合结果为：")
        print(self.result)
