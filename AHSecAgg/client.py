from utils import *
from init import *
import random
import json
import numpy as np
import socket
import threading

class client(object):
    def __init__(self, idnum: int, port: int):
        self.port = port
        self.idNum = idnum
        self.secretInput = np.random.randint(1, upbound, size = dimension, dtype='int64')
        
        self.secMaskKey = random.randint(1, upbound);
        
        #print('sec',self.secMaskKey)
        
        #self.privateKeyforMask = random.randint(1, upbound)
        #self.pubilcKeyforMask = binpow(DHg, self.privateKeyforMask, DHp)
        
        self.privateKeyforAec = random.randint(1, DHp)
        self.pubilcKeyforAec = binpow(DHg, self.privateKeyforAec, DHp)
        
        #self.maskKeyShares = []#SS.genShares(self.privateKeyforMask, t, n)
        self.secMaskKeyShares = []#SS.genShares(self.secMaskKey, t, n)
        
        #self.MaskCommonKeys = dict()
        self.AecCommonKeys = dict()
        
        self.pubkeyMsg_send = ''
        #self.pubkeyMsg_rece = dict()
        
        self.sharesMsg_send = dict() # 发送时增加 from_id
        #self.sharesforMask = dict()
        self.sharesforSec = dict()
        self.yus = dict()

        self.u1 = []
        self.u2 = []
        self.u3 = []
        self.u4 = []
       
        t_receive=threading.Thread(target=self.receivefromSingle,args=())
        t_receive.start() 
        

        
        self.sharesFlagSend = 0
        self.maskMsgFlagSend = 0
        self.unmaskMagFlagSend = 0
        
    #Round 0
    def genCommonKey(self, receive: dict):
        #self.MaskCommonKeys.clear()
        self.AecCommonKeys.clear()
        for i in receive:
            if(int(i) == self.idNum):
                continue
            #tpkey1 = binpow(receive[i]['maskKey'], self.privateKeyforMask, DHp)
            #self.MaskCommonKeys[int(i)] = tpkey1
            tpkey2 = binpow(receive[i]['aecKey'], self.privateKeyforAec, DHp)
            self.AecCommonKeys[int(i)] = tpkey2
        #print(self.AecCommonKeys)   
        #print(self.MaskCommonKeys)   
    
    def genPubkeyMsg(self):
        self.pubkeyMsg_send = ''
        msg = dict()
        msg['id'] = self.idNum
        #msg['maskKey'] = self.pubilcKeyforMask
        msg['aecKey'] = self.pubilcKeyforAec
        msg['port'] = self.port
        self.pubkeyMsg_send = msg
    
    #Round 1 
    def genSharesMsg(self, ids: list):
        #print(ids)
        self.sharesMsg_send.clear()
        self.sharesMsg_send['from_id'] = self.idNum
        self.sharesMsg_send['msg'] = {}
        nodeNum = len(ids)
        thres = nodeNum // 3 + 1
        self.secMaskKeyShares = genShares(self.secMaskKey, thres, self.u1, DHp)
        #self.maskKeyShares = genShares(self.privateKeyforMask, thres, self.u1, DHp)
        msg = dict()
        for i in range(len(ids)):
            if(int(ids[i]) == self.idNum):
                continue
            #msg['mask'] = self.maskKeyShares[int(ids[i])]
            msg['sec'] = self.secMaskKeyShares[int(ids[i])]
            self.sharesMsg_send['msg'][int(ids[i])] = AES_en(str(self.AecCommonKeys[ids[i]]), json.dumps(msg))
        #print(self.maskKeyShares)
        #print(self.secMaskKeyShares)
        
    def receShares(self, receive: dict):
        #self.sharesforMask.clear()
        self.sharesforSec.clear()
        for i in receive:
            #print(type(i))
            #print(receive[i])
            if(int(i) == self.idNum):
                continue
            msg = json.loads(AES_de(str(self.AecCommonKeys[int(i)]), receive[i]['msg'][str(self.idNum)]))
            #self.sharesforMask[int(i)] = msg['mask']
            self.sharesforSec[int(i)] = msg['sec']
        self.sharesforSec[self.idNum] = self.secMaskKeyShares[self.idNum]
    
    #Round2
    def genMaskMsg(self, ids: list) -> str:
        send = dict()
        yu = self.secretInput
        #prg = PRG(self.secMaskKey)
        tmp = (r * self.secMaskKey) % DHp
        for i in range(len(yu)):
            #yu[i] += prg.genRandint()
            yu[i] = (yu[i]+tmp) % DHp
            tmp = (tmp * r) % DHp
        send['id'] = self.idNum
        send['yu'] = NdarryToStr(yu)
        #send = json.dumps(send)
        return send
    
    #Round3
    def genRecoverMsg(self, ids: list) -> str:
        #print(self.sharesforMask)
        #print(self.sharesforSec)
        whose = 0
        
        for i in ids:
            whose = (whose + self.sharesforSec[i]) % DHp
        send = dict()
        send['from_id'] = self.idNum
        send['msg'] = whose
        #send = json.dumps(send)
        return send

    def receivefromSingle(self):
        '''
        msg_type:
        1：公钥
        2：私钥份额
        3：maskMsg
        '''
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((localhost, self.port))
        s.listen(10)
        self.u1.clear()
        self.u2.clear()
        self.u3.clear()
        self.u4.clear()
        
        while(True):
            sock, addr = s.accept()
            data=sock.recv(max(65536, 1024 * len(self.u1)))#缓冲区
            #print(data)
            buffer = json.loads(data)  # 设置缓冲器，指定一次接收的数据量
            print("收到的消息为：")
            print(buffer)
            #print("\n")
            sock.close()
            if(buffer[1] == 0):
                break
            elif(buffer[1] == 1):
                self.genCommonKey(buffer[2]['pubkeys'])
                self.u1 = buffer[2]['idlist']
                self.genSharesMsg(buffer[2]['idlist'])
                self.sharesFlagSend = 1
            elif(buffer[1] == 2):
                self.receShares(buffer[2]['msg'])
                self.u2 = buffer[2]['idlist']
                self.maskMsgFlagSend = 1
            elif(buffer[1] == 3):
                self.u3 = buffer[2]['idlist']
                self.unmaskMagFlagSend = 1
                self.yus = buffer[2]['msg']

    def sendtoServer(self, send_message, tar_port: int, msg_type: int):
        '''
        msg_type:
        0：退出接收
        1：公钥消息
        2：份额消息
        3：掩码消息
        4：恢复份额消息
        5：退出接收
        '''
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((localhost, tar_port))
        message=[self.port, msg_type, send_message]
        msg_send=json.dumps(message)
        s.send(msg_send.encode())
        s.close()

    def exitReceive(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((localhost, self.port))
        message=[self.port,0]
        msg_send=json.dumps(message)
        s.send(msg_send.encode())
        s.close()

    def startRound(self):
        #print("隐私输入为：")
        #print(self.secretInput)
        #print("\n")
        self.genPubkeyMsg()
        self.sendtoServer(self.pubkeyMsg_send, server_port, 1)
        while(self.sharesFlagSend == 0):
            pass
        sendMassage = {'from_id': self.idNum, 'msg': self.sharesMsg_send}
        
        self.sendtoServer(sendMassage, server_port, 2)
        self.sharesFlagSend = 0
        while(self.maskMsgFlagSend == 0):
            pass
        self.sendtoServer(self.genMaskMsg(self.u2), server_port, 3)
        self.maskMsgFlagSend = 0
        while(self.unmaskMagFlagSend == 0):
            pass
        self.sendtoServer(self.genRecoverMsg(self.u3), server_port, 4)
        self.unmaskMagFlagSend = 0
        
        self.exitReceive()
    
    def simDropout(self):
        #print("隐私输入为：")
        #print(self.secretInput)
        #print("\n")
        self.genPubkeyMsg()
        self.sendtoServer(self.pubkeyMsg_send, server_port, 1)
        while(self.sharesFlagSend == 0):
            pass
        sendMassage = {'from_id': self.idNum, 'msg': self.sharesMsg_send}
        self.sendtoServer(sendMassage, server_port, 2)
        
        self.exitReceive()