import time
from builtins import print

import pyshark
import glob
import os
import platform
from threading import Thread


class Protocol:
    protocol = {
        "tcp" : "1",
        "icmp" : "1",
        "udp" : "1",
    }


class HandlePcap:

    # Return "" if value equal None
    def cvNonetoStr(self, var):
        if var == None:
            return ""
        else:
            return var

    # Check has attribute
    def check_hasattr(self, parent, child):
        if hasattr(parent, child):
            return True;
        return False;

    # 1- Get Source ip
    def get_src_ip(self, packet):
        src_ip = 0
        if self.check_hasattr(packet, "ip"):
            src_ip = packet.ip.src_host
        return str(src_ip)

    # 2- Get Destination ip
    def get_dst_ip(self, packet):
        dst_ip = 0
        if self.check_hasattr(packet, "ip"):
            dst_ip = packet.ip.dst_host
        return str(dst_ip)

    # 3 - Get Source port
    def get_src_port(self, packet, protocol):
        src_port = 0
        if self.check_hasattr(packet, protocol):
            if self.check_hasattr(packet[protocol], "srcport"):
                src_port = packet[protocol].srcport
        return str(src_port)

    # 4 - Get Destination port
    def get_dst_port(self, packet, protocol):
        dst_port = 0
        if self.check_hasattr(packet, protocol):
            if self.check_hasattr(packet[protocol], "dstport"):
                dst_port = packet[protocol].dstport
        return str(dst_port)

    # 5- Get protocol
    def get_protocol(self, packet):
        protocol = "other"
        protocolDic = Protocol.protocol
        if self.check_hasattr(packet, "frame_info"):
            split = str(packet.frame_info.protocols).split(":")
            i = 0
            while i < len(split):
                protocol = protocolDic.get(split[i])
                if protocol != None:
                    protocol = split[i]
                    break
                i += 1
        if protocol == None:
            protocol = "other"
        return protocol

    # 6 - Get number of packet has same source ip
    # 7 - Get number of packets to dst_ip per protocol
    # 8 - get number of bytes from src_ip
    # 9 - Get number of bytes to dst_ip per protocol
    # 10 - Count same src_ip, src_port  to difference dst_ip, dst_port
    # 11 - Count diff src_ip, src_port  to same dst_ip, dst_port
    # 12 - get Land
    def get_calculate_feature(self, protocol, src_ip, src_port, dst_ip, dst_port, temp_pcap):
        src_packets = 0
        dst_packets = 0
        src_bytes = 0
        dst_bytes = 0
        ssrc_diff_dst = 0
        sdst_diff_src = 0
        land = 0
        for packet in temp_pcap:
            if protocol == self.get_protocol(packet) and src_ip == self.get_src_ip(packet):
                src_packets += 1
            if protocol == self.get_protocol(packet) and dst_ip == self.get_dst_ip(packet):
                dst_packets += 1
            if protocol == self.get_protocol(packet) and src_ip == self.get_src_ip(packet):
                src_bytes += int(packet.frame_info.len)
            if protocol == self.get_protocol(packet) and dst_ip == self.get_dst_ip(packet):
                dst_bytes += int(packet.frame_info.len)
            if src_ip == self.get_src_ip(packet) and src_port == self.get_src_port(packet, protocol) \
                    and (
                    dst_ip != self.get_dst_ip(packet) or dst_port != self.get_dst_port(packet, protocol)):
                ssrc_diff_dst += 1
            if dst_ip == self.get_dst_ip(packet) and dst_port == self.get_dst_port(packet, protocol) \
                    and (
                    src_ip != self.get_src_ip(packet) or src_port != self.get_src_port(packet, protocol)):
                sdst_diff_src += 1
            if src_ip == self.get_src_ip(packet) and src_ip == self.get_dst_ip(packet) \
                    and src_port == self.get_src_port(packet, protocol) and src_port == self.get_dst_port(packet, protocol):
                land += 1
        return str(src_packets) + "," + str(dst_packets) + "," + str(src_bytes) + "," + str(dst_bytes) + "," + str(ssrc_diff_dst) + "," + str(sdst_diff_src) + "," + str(land)

    def get_extract_path(self, src_path):
        fileExtract = ""
        if platform.system() == "Windows":
            list = src_path.split("\\")
            fileExtract = os.getcwd() + "\\DatasetTest\\" + list[-1].replace("pcap", "csv")
        elif platform.system() == "Linux":
            list = src_path.split("/")
            fileExtract = os.getcwd() + "/DatasetTest/" + list[-1].replace("pcap", "csv")
        else:
            print("Sorry, we do not support your system")
        return fileExtract

    def getFeature(self, src_path):
        i = 0
        FILEPATH = src_path
        if os.path.getsize(FILEPATH) > 268:
            print("Start: " + FILEPATH)
            FILE_EXTRACT_PATH = self.get_extract_path(FILEPATH)
            pcap = pyshark.FileCapture(FILEPATH)
            featureTotal = ""
            featureStr = ""
            featureSet = set()
            for packet in pcap:
                temp_pcap = pcap
                i += 1
                print(i)
                protocol = self.get_protocol(packet)
                if protocol != "other":
                    featureStr = ""
                    featureStrTuple = ""
                    src_ip = self.get_src_ip(packet)
                    dst_ip = self.get_dst_ip(packet)
                    src_port = self.get_src_port(packet, protocol)
                    dst_port = self.get_dst_port(packet, protocol)

                    featureStrTuple += src_ip + ","
                    featureStrTuple += dst_ip + ","
                    featureStrTuple += src_port + ","
                    featureStrTuple += dst_port + ","
                    featureStrTuple += protocol + ","

                    if featureStrTuple not in featureSet:
                        featureSet.add(featureStrTuple)
                    else:
                        continue

                    calcu_feature = self.get_calculate_feature(protocol, src_ip, src_port, dst_ip, dst_port, temp_pcap)

                    featureStr += src_ip + ","
                    featureStr += dst_ip + ","
                    featureStr += src_port + ","
                    featureStr += dst_port + ","
                    featureStr += protocol + ","
                    featureStr += calcu_feature
                    featureStr += "\n"
                    # if featureStr not in featureSet:
                    #     featureSet.add(featureStr)
                    featureTotal += featureStr
            if featureTotal != "":
                f = open(FILE_EXTRACT_PATH, "w+")
                f.write(featureTotal)
                f.close()
            #     pcap.close()
            print("Done: " + FILEPATH)


def featureExtract():

    handlePcap = HandlePcap()
    LASTFILE = ""
    curDirWorking = ""
    if platform.system() == "Windows":
        curDirWorking = os.getcwd() + "\\PcapCapture\\*"
    elif platform.system() == "Linux":
        curDirWorking = os.getcwd() + "/PcapCapture/*"
    else:
        print("Sorry, we do not support your system")
    # while True:
    # * means all if need specific format then *.pcap
    list_of_files = glob.glob(curDirWorking)
    if len(list_of_files) != 0:
        latest_file = max(list_of_files, key=os.path.getctime)
        if LASTFILE != latest_file:
            LASTFILE = latest_file
            time.sleep(2)
            thread = Thread(target=handlePcap.getFeature(LASTFILE))
            thread.start()

        # time.sleep(0.1)
