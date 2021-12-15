# -*- coding: utf-8 -*-
import os
import time
import socket
import logging
import threading
import yaml

from scapy.all import *
from pathlib import Path

from scapy.layers.inet import ICMP
from scapy.layers.l2 import *
from scapy.layers.inet6 import IP, UDP

socket.setdefaulttimeout(20)

BUF_SIZE = 1024
SERVER_NUM = 1


def get_logger():
    """ 打印的日志文件在本项目目录的/Logs下 """
    logger = logging.getLogger()
    logging.basicConfig(level=logging.INFO)

    rq = time.strftime('%Y%m%d%H%M%S', time.localtime(time.time()))
    log_path = os.path.dirname(os.getcwd() + '/Logs/')

    if not Path(log_path).is_dir():
        os.makedirs(log_path)

    log_name = os.path.join(log_path, rq + '.log')
    fh = logging.FileHandler(log_name, mode='w')
    # fh = logging.FileHandler('./Logs/test.log', mode='w')
    fh.setLevel(logging.INFO)

    formatter = logging.Formatter("%(asctime)s: %(message)s")
    fh.setFormatter(formatter)
    logger.addHandler(fh)
    return logger


class UDPServer:
    ipaddr = '10.0.102.79'
    port = 9996
    family = socket.AF_INET
    protocol = socket.SOCK_DGRAM
    logger = None

    def __init__(self):
        """ 只是一个给予python socket库写的发包，
        在本次项目中没有用处，但可以做测试

        :param logger: 避免全局搜索logger带来的混乱，这里直接传入logger
        """
        self.local_ip_address = self.get_local_ip_address()

    def get_local_ip_address(self):
        """ 获取本地ip地址 """
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip

    def send(self, data):
        """ 发包

        :param data: 列表，一次多段发包
        :return: 无
        """
        import random
        self.client = socket.socket(self.family, self.protocol)
        self.client.connect((self.ipaddr, self.port))

        for d in data:
            self.client.sendall(d)
            # data_recv = self.client.recvfrom(BUF_SIZE) # 只是发包，没法阻塞

        secs = random.random()
        time.sleep(secs)
        self.client.close()


class PcapFileExtractor(object):
    datagram = []

    remote_mac_address = ''
    remote_ip_address = '10.0.107.61'
    remote_ipv6 = ''
    remote_port = 9996

    pyshark_data = []

    def __init__(self, file_path, config):
        self.file_path = file_path
        self.local_mac_address = self.get_local_mac_address()
        self.local_ip_address = self.get_local_ip_address()
        self.local_ipv6 = self.get_local_ipv6()
        self.local_port = 9996

        self.__dict__.update(**config)

        # for k, v in self.__dict__.items():
        #     self.logger.info(f"{k}={v}")

    def scapy_extractor(self):
        """ 使用scapy获取pcap文件中所有的包，并重新生成数据包，放入列表中返回

        :return: 含有整理后的数据包的列表
        """
        packets = rdpcap(self.file_path)
        ps = []
        for packet in packets:
            # 确认该包是cflow
            if packet.getlayer('Netflow Header'):
                version = packet.getlayer('Netflow Header').fields['version']
                # 确认版本号v5或者v9
                if version in [5, 9]:
                    layer = packet.getlayer('Netflow Header')
                    layer.__delattr__('sysUptime')
                    layer.__delattr__('unixSecs')

                    # udp包
                    # pkt = Ether(dst=self.remote_mac_address) / IP(
                    #     dst=self.remote_ip_address) / UDP(dport=self.remote_port)

                    # icmp包
                    # pkt = IP(self.remote_ip_address) / ICMP()

                    # netflow的包
                    pkt = IP(dst=self.remote_ip_address)/UDP(dport=self.remote_port)/packet.getlayer('Netflow Header')
                    ps.append(pkt)
        return ps

    def pyshark_extractor(self):
        """ 使用pyshark获取包，但因为难以重新整理，该功能废除，仅能作为读取分析使用

        :return: pyshark读取的sflow与cflow数据包的列表
        """
        import pyshark
        packets = pyshark.FileCapture(self.file_path)
        idx = 0
        for packet in packets:
            if 'sflow' in dir(packet):
                idx = self._make_data('sflow', packet, idx)
            if 'cflow' in dir(packet):
                idx = self._make_data('cflow', packet, idx)
        packets.close()
        return self.pyshark_data

    def _make_data(self, name, packet, idx):
        """ 配合pyshark获取包，挖掘udp中的payload """
        if 'data' in dir(packet.layers[-1]):
            idx += 1
            self.pyshark_data.append([layer.binary_value
                                      for layer in packet.layers[-1].pyshark_data.all_fields])
            # self.data.append(b''.join([layer.binary_value
            #                    for layer in packet.layers[-1].data.all_fields]))
            time.sleep(0.5)
        return idx

    def get_local_mac_address(self):
        """ 获取本地mac地址 """
        import uuid
        mac = uuid.UUID(int=uuid.getnode()).hex[-12:]
        return ":".join([mac[e:e + 2] for e in range(0, 11, 2)])

    def get_local_ip_address(self):
        """ 获取本地IP地址 """
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip

    def get_local_ipv6(self):
        """ 获取本地ipv6的地址，但是会出错，尽可能人工写入 """
        import socket
        ipv6 = ''
        groups = socket.getaddrinfo(socket.gethostname(), None)
        for group in groups:
            if group[0].name == 'AF_INET6':
                ipv6 = group[4][0]
                break
        return ipv6


def get_handler_config():
    filepath = os.path.dirname(__file__)
    path = os.path.join(filepath, 'config.yaml')

    with open(path, 'r', encoding='utf-8') as f:
        conf = yaml.load(f.read(), Loader=yaml.FullLoader)

    return conf


def scapy_send_package(number, worker, pkts):
    """ 为多线程创建的发包函数 """
    idx = 1
#    while True:
    for j in range(len(pkts)):
        send(pkts[j])
    print(len(pkts))
    idx += 1


if __name__ == '__main__':
    # logger = get_logger()
    # logger.info('PCAP Replay starts!')

    try:
        # 获取参数与获取数据包
        config = get_handler_config()
        remote_info = config.get('remote_info')
        if remote_info:
            port = remote_info.get('remote_port')
            if port:
                remote_info['remote_port'] = int(port)

        extractor = PcapFileExtractor(config.get('server').get('pcap_file'), remote_info)
        pkts = extractor.scapy_extractor()

        # 获取线程数与服务器编号
        workers = config.get('server').get('workers')
        number = config.get('server').get('number')

        # 多线程发送
        threads = []
        for i in range(workers):
            t = threading.Thread(target=scapy_send_package, args=(number, i+1, pkts))
            threads.append(t)

        for i in range(workers):
            threads[i].start()

        for i in range(workers):
            threads[i].join()
    except Exception as e:
        print(e.__repr__())
        print("Failed to activate threads.")
        # logger.info('Failed to activate threads.')

    # 使用socket发送udp包
    # udp = UDPServer(logger)
    # while True:
    #     udp.send([b'hello'])
    # for value in data:
    #     udp.send(value)
