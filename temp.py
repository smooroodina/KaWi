# 기능별로 모듈을 구분해 개발하기 전에 이 파일에서 작성하여 잘 작동하는지 실행시켜 봅니다.
import os
import sys
from PyQt5 import QtCore, QtGui, QtWidgets

sys.path.append(os.path.dirname(os.path.abspath(__file__)) + '\\scapy')
from scapy.all import *     # noqa: E402


class SnifferThread(QtCore.QThread):
    HandleSignal = QtCore.pyqtSignal(scapy.layers.l2.Ether)

    def __init__(self, filter, iface):
        super().__init__()
        self.filter = filter
        self.iface = iface

    def run(self):
        sniff(filter=self.filter, iface=self.iface, prn=lambda x: self.HandleSignal.emit(x))

    # def pack_callback(self,packet):
    #     packet.show()


def set_monitor_mode(iface):
    # todo: 환경변수에 Npcap 경로 설정
    try:
        subprocess.check_call(['WlanHelper.exe', iface, 'mode', 'monitor'])
        print(f"Interface {iface} set to monitor mode.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to set {iface} to monitor mode: {e}")


# Recognizes and returns a list of network interface.
#   [Input] none
#   [Output] List of available network interface [Name, Description, MAC, IPv4]
## Test Requirements:
##  - 네트워크 인터페이스 정보를 명확하게 불러오는지
##  - Windows 기반으로만 작동 확인했으므로 Linux에서 정상 동작하는지
##  -- 사용 안 하는(DOWN 상태인) 인터페이스를 표시하지 않아야 함
def lookup_iface():
    iface_list = []
    for guid, iface in conf.ifaces.data.items():
        if iface.mac != '':  # Windows에서 WAN Miniport 제외
            iface_list.append(iface)
    return iface_list


if __name__ == '__main__':
    ap_list = []

    # Callback function that executes with each packet sniffed.
    #   [Input] a packet
    #   [Output] none
    def packet_handler(packet):
        # Print summary information of the packet
        # print(packet.summary())
        if packet.type == 0 and packet.subtype == 8:
            if packet.addr2 not in ap_list:
                ap_list.append(packet.addr2)
                print("AP MAC: %s with SSID: %s " % (packet.addr2, (packet.info).decode('utf-8')))


    # Get my network interface name list
    iface_list = lookup_iface()
    # select one, set to conf.iface
    # ...
    conf.iface = next((i for i in iface_list if i.description == '802.11n USB Wireless LAN Card'), None)
    # can choose whether to sniff in monitor mode or not.
    monitor = True
    # params for sniff(): scapy/scapy/sendrecv.py - class AsyncSniffer - def _run(...) 참고.
    # iface 명시하지 않으면 자동으로 conf.iface의 인터페이스가 선택됨
    sniff(prn=packet_handler, monitor=monitor)
