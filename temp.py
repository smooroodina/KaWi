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





if __name__ == '__main__':
