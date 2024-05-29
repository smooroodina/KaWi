import os, sys
from PyQt5.QtWidgets import *
from PyQt5 import uic, QtWidgets
from PyQt5.QtCore import QTimer

sys.path.append(os.path.dirname(os.path.abspath(__file__)) + '\\scapy')
from scapy.all import *

def resource_path(relative_path):
    base_path = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_path, relative_path)

form = resource_path('main.ui')
form_Sniffer = uic.loadUiType(form)[0]

class MainWindow(QMainWindow, form_Sniffer):
    def __init__(self):
        super().__init__()
        self.setupUi(self)
        self.initUI()
        self.setWindowTitle("KaWi")
        self.show()

    def initUI(self):
        self.Sniff_chk_monitorMode.stateChanged.connect(self.handleButtonClick)
        self.Sniff_toggleButton.clicked.connect(self.handleButtonClick)
        self.Sniff_setButton.clicked.connect(self.move_to_next_tab)

        self.Sniff_toggleButton.clicked.connect(self.add_rows)
        self.captured_packets.itemSelectionChanged.connect(self.on_row_selected)
        self.captured_packets.itemSelectionChanged.connect(self.clickInfo)

        self.Spoof_toggleButton.clicked.connect(self.toggleProgress)
        self.KRACK_toggleButton.clicked.connect(self.toggleProgress)
        self.Spoof_timer = QTimer(self)
        self.Spoof_timer.timeout.connect(self.Spoof_updateProgress)
        self.KRACK_timer = QTimer(self)
        self.KRACK_timer.timeout.connect(self.KRACK_updateProgress)
        self.progress_value = 0

    def toggleProgress(self):
        sender = self.sender()  # 이벤트를 발생시킨 위젯 확인
        if isinstance(sender, QPushButton):  # 발생시킨 위젯이 QPushButton이면
            self.progress_value = 0
            if sender.objectName() == "Spoof_toggleButton":
                self.Spoof_timer.start(100)
                if sender.text() == "Start":
                    self.Spoof_Info.clear()
                    sender.setText("Stop")
                else:
                    self.Spoof_timer.stop()
                    sender.setText("Start")

            elif sender.objectName() == "KRACK_toggleButton":
                self.KRACK_timer.start(100)

                if sender.text() == "Start":
                    self.KRACK_Info.clear()
                    sender.setText("Stop")
                    self.radio_Replay_Broadcast.setEnabled(False)
                    self.radio_Test_GTK.setEnabled(False)
                    self.radio_Test_KRACK.setEnabled(False)
                    self.radio_KRACK_Attack.setEnabled(False)
                    self.radio_Entire.setEnabled(False)

                    if self.radio_Replay_Broadcast.isChecked():
                        QMessageBox.information(self, "Radio", "radio_Replay_Broadcast")
                    if self.radio_Test_GTK.isChecked():
                        QMessageBox.information(self, "Radio", "radio_Test_GTK")
                    elif self.radio_Test_KRACK.isChecked():
                        QMessageBox.information(self, "Radio", "radio_Test_KRACK")
                    elif self.radio_KRACK_Attack.isChecked():
                        QMessageBox.information(self, "Radio", "radio_KRACK_Attack")
                    elif self.radio_Entire.isChecked():
                        QMessageBox.information(self, "Radio", "radio_Entire")

                else:
                    sender.setText("Start")
                    self.KRACK_timer.stop()
                    self.radio_Replay_Broadcast.setEnabled(True)
                    self.radio_Test_GTK.setEnabled(True)
                    self.radio_Test_KRACK.setEnabled(True)
                    self.radio_KRACK_Attack.setEnabled(True)
                    self.radio_Entire.setEnabled(True)

    def Spoof_updateProgress(self):
        self.progress_value += 1
        if self.progress_value > 100:
            self.Spoof_timer.stop()
            self.Spoof_toggleButton.setText("Start")
            QMessageBox.information(self, "Spoofing", "작업 완료")
            return
        self.Spoof_Info.append(f'{self.progress_value}')
        self.Spoof_pBar.setValue(self.progress_value)

    def KRACK_updateProgress(self):
        self.progress_value += 1
        if self.progress_value > 100:
            self.KRACK_timer.stop()
            self.KRACK_toggleButton.setText("Start")
            self.radio_Replay_Broadcast.setEnabled(True)
            self.radio_Test_GTK.setEnabled(True)
            self.radio_Test_KRACK.setEnabled(True)
            self.radio_KRACK_Attack.setEnabled(True)
            self.radio_Entire.setEnabled(True)
            QMessageBox.information(self, "KRACK", "작업 완료")
            return
        self.KRACK_Info.append(f'{self.progress_value}')
        self.KRACK_pBar.setValue(self.progress_value)

    def handleButtonClick(self):
        sender = self.sender()  # 이벤트를 발생시킨 위젯 확인
        if isinstance(sender, QCheckBox):  # 발생시킨 위젯이 QCheckBox이면
            if sender.isChecked():
                QMessageBox.information(self, "Checkbox Checked", f"{sender.text()} 체크박스 선택")
            else:
                QMessageBox.information(self, "Checkbox Unchecked", f"{sender.text()} 체크박스 해제")
        elif isinstance(sender, QPushButton):  # 발생시킨 위젯이 QPushButton이면
            if sender.text() == "Start":
                QMessageBox.information(self, "Start", "시작 버튼 선택")
                sender.setText("Stop")
            else:
                QMessageBox.information(self, "Stop", "정지 버튼 선택")
                sender.setText("Start")

    def move_to_next_tab(self):
        current_index = self.tabs.currentIndex()
        next_index = (current_index + 1) % self.tabs.count()
        self.tabs.setCurrentIndex(next_index)

    def add_rows(self):
        row_position = self.captured_packets.rowCount()
        self.captured_packets.insertRow(row_position)

        self.captured_packets.setItem(row_position, 0, QTableWidgetItem("No"))
        self.captured_packets.setItem(row_position, 1, QTableWidgetItem("Time"))
        self.captured_packets.setItem(row_position, 2, QTableWidgetItem("source"))
        self.captured_packets.setItem(row_position, 3, QTableWidgetItem("Dest"))
        self.captured_packets.setItem(row_position, 4, QTableWidgetItem("Protocol"))
        self.captured_packets.setItem(row_position, 5, QTableWidgetItem("Length"))
        self.captured_packets.setItem(row_position, 6, QTableWidgetItem("Content"))

    def on_row_selected(self):
        selected_indexes = self.captured_packets.selectionModel().selectedIndexes()
        if selected_indexes:
            selected_row = selected_indexes[0].row()
            QMessageBox.information(self, "Packet", f"{selected_row}")

    def clickInfo(self):
        row = self.captured_packets.currentRow()
        # packet = scapy.layers.l2.Ether(p.encode('Windows-1252'))

        no = self.captured_packets.item(row, 0).text()
        time = self.captured_packets.item(row, 1).text()
        src = self.captured_packets.item(row, 2).text()
        dst = self.captured_packets.item(row, 3).text()
        protocol = self.captured_packets.item(row, 4).text()
        length = self.captured_packets.item(row, 5).text()
        content = self.captured_packets.item(row, 6).text()

        # iface = self.iface
        # import time
        # timeformat = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(packet.time))

        self.PacketInfo.clear()
        self.PacketInfo.setColumnCount(1)

        # Frame
        Frame = QtWidgets.QTreeWidgetItem(self.PacketInfo)
        Frame.setText(0, 'Frame %s：%s bytes on %s' % (no, length, "Realtek"))
        FrameIface = QtWidgets.QTreeWidgetItem(Frame)
        FrameIface.setText(0, '장비명 : something')
        FrameArrivalTime = QtWidgets.QTreeWidgetItem(Frame)
        FrameArrivalTime.setText(0, '도착 시간 : 00:00')
        FrameTime = QtWidgets.QTreeWidgetItem(Frame)
        FrameTime.setText(0, '첫 번째 프레임 도착 시간 : ')
        FrameNumber = QtWidgets.QTreeWidgetItem(Frame)
        FrameNumber.setText(0, '번호 : %s' % no)
        FrameLength = QtWidgets.QTreeWidgetItem(Frame)
        FrameLength.setText(0, '길이：%s' % length)

        # Ethernet
        Ethernet = QtWidgets.QTreeWidgetItem(self.PacketInfo)
        Ethernet.setText(0, 'Ethernet，출발 MAC 주소(src)：' + "packet.src" + '，목적 MAC 주소(dst)：' + "packet.dst")
        EthernetDst = QtWidgets.QTreeWidgetItem(Ethernet)
        EthernetDst.setText(0, '목적 MAC 주소(dst)：' + "packet.dst")
        EthernetSrc = QtWidgets.QTreeWidgetItem(Ethernet)
        EthernetSrc.setText(0, '출발 MAC 주소(src)：' + "packet.src")

        # self.textBrowserRaw.clear()
        # if packet.haslayer('Raw'):
        #     # raw = QtWidgets.QTreeWidgetItem(self.treeWidget)
        #     # raw.setText(0,'Raw：%s' % packet[Raw].load.decode('utf-8','ignore'))
        #     self.textBrowserRaw.append('Raw：%s' % packet[Raw].load.decode('utf-8', 'ignore'))
        #
        # if packet.haslayer('Padding'):
        #     # padding = QtWidgets.QTreeWidgetItem(self.treeWidget)
        #     # padding.setText(0,'Padding：%s' % packet[Padding].load.decode('utf-8','ignore'))
        #     self.textBrowserRaw.append('Padding：%s' % packet[Padding].load.decode('utf-8', 'ignore'))
        #
        # self.textBrowserDump.clear()
        # f = open('hexdump.tmp', 'w')
        # old = sys.stdout
        # sys.stdout = f
        # hexdump(packet)
        # sys.stdout = old
        # f.close()
        # f = open('hexdump.tmp', 'r')
        # content = f.read()
        # self.textBrowserDump.append(content)
        # f.close()
        # os.remove('hexdump.tmp')

if __name__ == "__main__":
    app = QApplication(sys.argv)
    myWindow = MainWindow()
    sys.exit(app.exec_())
