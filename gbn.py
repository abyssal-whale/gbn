"""
gbn.py
~~~~~~
This module implements the sender and receiver of SR Protocol.

:copyright: (c) 2022 by Zhihao Zhang.
:date: 2022/6/7
"""
import random
import socket
import struct
import time
import os
import threading

BUFFER_SIZE = 4096
TIMEOUT = 10
WINDOW_SIZE = 3
LOSS_RATE = 0.1


def getChecksum(data):
    """
    char_checksum 按字节计算校验和。每个字节被翻译为无符号整数
    @param data: 字节串
    """
    length = len(str(data))
    checksum = 0
    for i in range(0, length):
        checksum += int.from_bytes(bytes(str(data)[i], encoding='utf-8'), byteorder='little', signed=False)
        checksum &= 0xFF  # 强制截断

    return checksum


class GBNSender:
    def __init__(self, senderSocket, address, timeout=TIMEOUT,
                 windowSize=WINDOW_SIZE, lossRate=LOSS_RATE):
        self.sender_socket = senderSocket
        self.timeout = timeout
        self.address = address
        self.window_size = windowSize
        self.loss_rate = lossRate
        self.send_base = 0
        self.next_seq = 0
        self.packets = [None] * 256

    def udp_send(self, pkt):
        if self.loss_rate == 0 or random.randint(0, int(1 / self.loss_rate)) != 1:
            self.sender_socket.sendto(pkt, self.address)
        else:
            print('故意丢包')
        time.sleep(0.2)

    def GBN_send(self):
        self.sender_socket.settimeout(self.timeout)
        count = 0
        while True:
            if count >= 10:
                # 连续超时10次，接收方已断开，终止
                break
            try:
                data, address = self.sender_socket.recvfrom(BUFFER_SIZE)
                ack_seq, expect_seq = self.analyse_pkt(data)
                print('Sender receive ACK:ack_seq', ack_seq, "expect_seq", expect_seq)
                print("Send from window: ", ack_seq)
                if self.send_base == (ack_seq + 1) % 256:
                    # 收到重复确认, 此处应当立即重发
                    pass
                self.send_base = max(self.send_base, (ack_seq + 1) % 256)  # 窗口滑动
                if self.send_base == self.next_seq:  # 已发送分组确认完毕
                    self.sender_socket.settimeout(None)
                    return True

            except socket.timeout:
                # 超时，重发分组.
                print('超时')
                for i in range(self.send_base, self.next_seq):
                    print('Sender resend packet:', i)
                    self.udp_send(self.packets[i])
                self.sender_socket.settimeout(self.timeout)  # reset timer
                count += 1
        return False

    def SR_send(self, already_sent, received_ack):
        self.sender_socket.settimeout(self.timeout)
        count = 0
        while True:
            if count >= 10:
                # 连续超时10次，接收方已断开，终止
                break
            try:
                data, address = self.sender_socket.recvfrom(BUFFER_SIZE)
                ack_seq, expect_seq = self.analyse_pkt(data)
                print('Sender receive ACK:ack_seq', ack_seq, "expect_seq", expect_seq)
                print("Send from window: ", ack_seq)
                received_ack[ack_seq] = 1  # 记录收到的ACK
                if self.send_base == (ack_seq + 1) % 256:  # 收到重复确认, 此处应当立即重发
                    pass
                if self.send_base == ack_seq:
                    # 如果发送方的窗口未滑动，且没收到窗口中的某个片段重复确认，SR协议下将窗口滑动到此片段
                    while 1:
                        if received_ack[self.send_base] == 1:  # 滑动窗口
                            self.send_base = (self.send_base + 1) % 256
                            print("窗口滑动至序号：", self.send_base)
                        else:  # 停在未返回ack的片段处
                            break
                if self.send_base == self.next_seq:  # 已发送分组确认完毕
                    self.sender_socket.settimeout(None)
                    return True

            except socket.timeout:
                # 超时，重发分组.
                print('超时')
                for i in range(self.send_base, self.send_base + self.window_size):
                    # 检测重发范围比GBN方法中的要更大，因为窗口base之后windows_size大小的片段都可能已被传输
                    if already_sent[i] == 1 and received_ack[i] == 0:
                        # 如果分组已发送但是没有收到对应编号的ack
                        print('Sender resend packet:', i)
                        self.udp_send(self.packets[i])
                self.sender_socket.settimeout(self.timeout)  # reset timer
                count += 1
        return False

    def make_pkt(self, seqNum, data, checksum, stop=False):
        """
        将数据打包
        """
        flag = 1 if stop else 0
        return struct.pack('BBB', seqNum, flag, checksum) + data

    def analyse_pkt(self, pkt):
        """
        分析数据包
        """
        ack_seq = pkt[0]
        expect_seq = pkt[1]
        return ack_seq, expect_seq


class GBNReceiver:
    def __init__(self, receiverSocket, timeout=10, lossRate=0, windowSize=WINDOW_SIZE):
        self.receiver_socket = receiverSocket
        self.timeout = timeout
        self.loss_rate = lossRate
        self.window_size = windowSize
        self.expect_seq = 0
        self.target = None

    def udp_send(self, pkt):
        if self.loss_rate == 0 or random.randint(0, 1 / self.loss_rate) != 1:
            self.receiver_socket.sendto(pkt, self.target)
            print('Receiver send ACK:', pkt[0])
        else:
            print('Receiver send ACK:', pkt[0], ', but lost.')

    def GBN_receive(self):
        """
        接收方等待接受数据包
        """
        self.receiver_socket.settimeout(self.timeout)
        while True:
            try:
                data, address = self.receiver_socket.recvfrom(BUFFER_SIZE)
                self.target = address
                seq_num, flag, checksum, data = self.analyse_pkt(data)
                print('Receiver receive packet:', seq_num)
                # 收到期望数据包且未出错
                if seq_num == self.expect_seq and getChecksum(data) == checksum:
                    self.expect_seq = (self.expect_seq + 1) % 256
                    ack_pkt = self.make_pkt(seq_num, seq_num)
                    self.udp_send(ack_pkt)
                    if flag:  # 最后一个数据包
                        return data, True  # 向上层递交数据块
                    else:
                        return data, False
                else:
                    ack_pkt = self.make_pkt((self.expect_seq - 1) % 256, self.expect_seq)  # 重复确认，让客户回退N步重传
                    self.udp_send(ack_pkt)
                    return bytes('', encoding='utf-8'), False
            except socket.timeout:
                return bytes('', encoding='utf-8'), False

    def SR_receive(self, received_data, buffer):
        """
        接收方等待接受数据包
        """
        self.receiver_socket.settimeout(self.timeout)
        while True:
            try:
                data, address = self.receiver_socket.recvfrom(BUFFER_SIZE)
                self.target = address
                seq_num, flag, checksum, data = self.analyse_pkt(data)
                print('Receiver receive packet:', seq_num)
                received_data[seq_num] = 1
                # 收到期望数据包且未出错
                if seq_num == self.expect_seq and getChecksum(data) == checksum:
                    self.expect_seq = (self.expect_seq + 1) % 256
                    ack_pkt = self.make_pkt(seq_num, seq_num)
                    self.udp_send(ack_pkt)
                    for i in range(self.expect_seq, self.expect_seq + self.window_size):
                        # 只要是发过来的data就都缓存起来
                        if received_data[i] == 1:
                            data = data + buffer[i]
                            self.expect_seq = (self.expect_seq + 1) % 256  # 滑动接收窗口
                        else:  # 一旦遇到没发过来的data就停止缓存
                            break
                    if flag:  # 最后一个数据包
                        return data, True  # 向上层递交数据块
                    else:
                        return data, False
                elif seq_num < self.expect_seq and getChecksum(data) == checksum:
                    # 不管该分组是否已被确认，都必须生成一个ack
                    ack_pkt = self.make_pkt(seq_num, seq_num)
                    self.udp_send(ack_pkt)
                    return bytes('', encoding='utf-8'), False
                elif self.expect_seq < seq_num < self.expect_seq + self.window_size and getChecksum(
                        data) == checksum:
                    # 如果收到的分组在接收方的窗口内，一个选择ack被会送给发送方
                    received_data[seq_num] = 1
                    buffer[seq_num] = data
                    ack_pkt = self.make_pkt(seq_num, seq_num)
                    self.udp_send(ack_pkt)
                    return bytes('', encoding='utf-8'), False
                else:  # 忽略改分组
                    return bytes('', encoding='utf-8'), False
            except socket.timeout:
                return bytes('', encoding='utf-8'), False

    def analyse_pkt(self, pkt):
        """
        分析数据包
        """
        seq_num = pkt[0]
        flag = pkt[1]
        checksum = pkt[2]
        data = pkt[3:]
        if flag == 0:
            print("seq_num: ", seq_num, "not end ")
        else:
            print("seq_num: ", seq_num, " end ")
        return seq_num, flag, checksum, data

    def make_pkt(self, ackSeq, expectSeq):
        """
        创建ACK确认报文
        """
        return struct.pack('BB', ackSeq, expectSeq)


def Receive(receiver, fp):
    reset = False
    while True:
        data, reset = receiver.GBN_receive()
        print('Data length:', len(data))
        fp.write(data)
        if reset:
            receiver.expect_seq = 0
            fp.close()
            break


def Send(sender, fp):
    dataList = []
    while True:  # 把文件夹下的数据提取出来
        data = fp.read(2048)
        if len(data) <= 0:
            break
        dataList.append(data)
    print('The total number of data packets: ', len(dataList))
    pointer = 0
    while True:
        while sender.next_seq < (sender.send_base + sender.window_size):
            if pointer >= len(dataList):
                break
            # 发送窗口为被占满
            data = dataList[pointer]
            checksum = getChecksum(data)
            if pointer < len(dataList) - 1:
                sender.packets[sender.next_seq] = sender.make_pkt(sender.next_seq, data, checksum,
                                                                  stop=False)
            else:
                sender.packets[sender.next_seq] = sender.make_pkt(sender.next_seq, data, checksum,
                                                                  stop=True)
            print('Sender send packet:', pointer)
            sender.udp_send(sender.packets[sender.next_seq])
            sender.next_seq = (sender.next_seq + 1) % 256
            pointer += 1
        flag = sender.GBN_send()
        if pointer >= len(dataList):
            break
    fp.close()


def Send_SR(sender, fp):
    senderSendSet = []
    received_ack = []
    dataList = []
    while True:  # 把文件夹下的数据读取出来
        data = fp.read(2048)
        if len(data) <= 0:
            break
        dataList.append(data)
    print('The total number of data packets: ', len(dataList))
    for i in range(0, 100000):  # 初始化发送和接收标志
        senderSendSet.append(0)
        received_ack.append(0)
    pointer = 0
    while True:
        while sender.next_seq < (sender.send_base + sender.window_size) and senderSendSet[sender.next_seq] == 0:
            if pointer >= len(dataList):
                break
            # 发送窗口为被占满
            data = dataList[pointer]
            checksum = getChecksum(data)
            if pointer < len(dataList) - 1:
                sender.packets[sender.next_seq] = sender.make_pkt(sender.next_seq, data, checksum,
                                                                  stop=False)
            else:
                sender.packets[sender.next_seq] = sender.make_pkt(sender.next_seq, data, checksum,
                                                                  stop=True)
            print('Sender send packet:', pointer)
            sender.udp_send(sender.packets[sender.next_seq])
            senderSendSet[sender.next_seq] = 1  # 记录已发送的分组编号
            sender.next_seq = (sender.next_seq + 1) % 256
            pointer += 1
        flag = sender.SR_send(senderSendSet, received_ack)
        if pointer >= len(dataList):
            break
    fp.close()


def Receive_SR(receiver, fp):
    reset = False
    received_data = []
    buffer = []
    for i in range(0, 1000):
        received_data.append(0)
        buffer.append('')
    while True:
        data, reset = receiver.SR_receive(received_data, buffer)
        print('Data length:', len(data))
        fp.write(data)
        if reset:
            receiver.expect_seq = 0
            fp.close()
            break


fpSend_Client = open(os.path.dirname(__file__) + '/client/girl.jpg', 'rb')
fpSend_Server = open(os.path.dirname(__file__) + '/server/cartoon.jpg', 'rb')
fpReceive_Client = open(os.path.dirname(__file__) + '/client/' + str(int(time.time())) + '.jpg', 'ab')
fpReceive_Server = open(os.path.dirname(__file__) + '/server/' + str(int(time.time())) + '.jpg', 'ab')

Socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
Socket2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sender_client = GBNSender(Socket, ('127.0.0.1', 8888))
sender_server = GBNSender(Socket2, ('127.0.0.1', 7777))

receiverSocket_Client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
receiverSocket_Server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
receiverSocket_Client.bind(('', 7777))
receiverSocket_Server.bind(('', 8888))

Client_Send = threading.Thread(target=Send_SR, args=(sender_client, fpSend_Client,))
Server_Send = threading.Thread(target=Send_SR, args=(sender_server, fpSend_Server,))
Client_Receive = threading.Thread(target=Receive_SR, args=(GBNReceiver(receiverSocket_Client), fpReceive_Client,))
Server_Receive = threading.Thread(target=Receive_SR, args=(GBNReceiver(receiverSocket_Server), fpReceive_Server,))
Client_Send.start()
Server_Send.start()
Client_Receive.start()
Server_Receive.start()
