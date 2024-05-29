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

        # try:
        #     type = packet.type
        # except:
        #     type = 0

        # IP
        # if type == 0x800:
        #     EthernetType = QtWidgets.QTreeWidgetItem(Ethernet)
        #     EthernetType.setText(0, '유형(Type)：IPv4(0x800)')
        #
        #     IPv4 = QtWidgets.QTreeWidgetItem(self.treeWidget)
        #     IPv4.setText(0, 'IPv4，출발지(Src)：' + packet[IP].src + '，목적지(Dst)：' + packet[IP].dst)
        #     IPv4Version = QtWidgets.QTreeWidgetItem(IPv4)
        #     IPv4Version.setText(0, '버전(Version)：%s' % packet[IP].version)
        #     IPv4Ihl = QtWidgets.QTreeWidgetItem(IPv4)
        #     IPv4Ihl.setText(0, 'IP 헤더 길이(IHL)：%s' % packet[IP].ihl)
        #     IPv4Tos = QtWidgets.QTreeWidgetItem(IPv4)
        #     IPv4Tos.setText(0, '서비스 유형(ToS)：%s' % packet[IP].tos)
        #     IPv4Len = QtWidgets.QTreeWidgetItem(IPv4)
        #     IPv4Len.setText(0, '전체 길이(Len)：%s' % packet[IP].len)
        #     IPv4Id = QtWidgets.QTreeWidgetItem(IPv4)
        #     IPv4Id.setText(0, '식별 번호(ID)：%s' % packet[IP].id)
        #     IPv4Flags = QtWidgets.QTreeWidgetItem(IPv4)
        #     IPv4Flags.setText(0, 'Flags：%s' % packet[IP].flags)
        #     IPv4Frag = QtWidgets.QTreeWidgetItem(IPv4)
        #
        #     IPv4FlagsDF = QtWidgets.QTreeWidgetItem(IPv4Flags)
        #     IPv4FlagsDF.setText(0, 'Do not Fragment(DF)：%s' % packet[IP].flags.DF)
        #     IPv4FlagsMF = QtWidgets.QTreeWidgetItem(IPv4Flags)
        #     IPv4FlagsMF.setText(0, 'More Fragment(MF)：%s' % packet[IP].flags.MF)
        #
        #     IPv4Frag.setText(0, 'Fragment(Frag)：%s ' % packet[IP].frag)
        #     IPv4Ttl = QtWidgets.QTreeWidgetItem(IPv4)
        #     IPv4Ttl.setText(0, '패킷 수명(TTL)：%s' % packet[IP].ttl)

            # TCP
            # if packet[IP].proto == 6:
            #     if packet.haslayer('TCP'):
            #         IPv4Proto = QtWidgets.QTreeWidgetItem(IPv4)
            #         IPv4Proto.setText(0, '프로토콜(proto)：TCP(6)')
            #         tcp = QtWidgets.QTreeWidgetItem(self.treeWidget)
            #         tcp.setText(0, 'TCP，출발 포트(sport)：%s，도착 포트(dport)：%s，Seq：%s，Ack：%s' % (packet[TCP].sport, packet[TCP].dport, packet[TCP].seq, packet[TCP].ack))
            #         tcpSport = QtWidgets.QTreeWidgetItem(tcp)
            #         tcpSport.setText(0, '출발 포트(sport)：%s' % packet[TCP].sport)
            #         tcpDport = QtWidgets.QTreeWidgetItem(tcp)
            #         tcpDport.setText(0, '도착 포트(dport)：%s' % packet[TCP].dport)
            #         tcpSeq = QtWidgets.QTreeWidgetItem(tcp)
            #         tcpSeq.setText(0, 'Seq：%s' % packet[TCP].seq)
            #         tcpAck = QtWidgets.QTreeWidgetItem(tcp)
            #         tcpAck.setText(0, 'Ack：%s' % packet[TCP].ack)
            #         tcpDataofs = QtWidgets.QTreeWidgetItem(tcp)
            #         tcpDataofs.setText(0, '데이터 오프셋(Data offset)：%s' % packet[TCP].dataofs)
            #         tcpReserved = QtWidgets.QTreeWidgetItem(tcp)
            #         tcpReserved.setText(0, 'Reserved：%s' % packet[TCP].reserved)
            #         tcpFlags = QtWidgets.QTreeWidgetItem(tcp)
            #         tcpFlags.setText(0, 'Flags：%s' % packet[TCP].flags)
            #
            #
            #         tcpFlagsACK = QtWidgets.QTreeWidgetItem(tcpFlags)
            #         tcpFlagsACK.setText(0, 'ACK：%s' % packet[TCP].flags.A)
            #         tcpFlagsRST = QtWidgets.QTreeWidgetItem(tcpFlags)
            #         tcpFlagsRST.setText(0, 'RST：%s' % packet[TCP].flags.R)
            #         tcpFlagsSYN = QtWidgets.QTreeWidgetItem(tcpFlags)
            #         tcpFlagsSYN.setText(0, 'SYN：%s' % packet[TCP].flags.S)
            #         tcpFlagsFIN = QtWidgets.QTreeWidgetItem(tcpFlags)
            #         tcpFlagsFIN.setText(0, 'FIN：%s' % packet[TCP].flags.F)
            #         tcpFlagsURG = QtWidgets.QTreeWidgetItem(tcpFlags)
            #         tcpFlagsURG.setText(0, 'URG：%s' % packet[TCP].flags.U)
            #         tcpFlagsPSH = QtWidgets.QTreeWidgetItem(tcpFlags)
            #         tcpFlagsPSH.setText(0, 'PSH：%s' % packet[TCP].flags.P)
            #         tcpWindow = QtWidgets.QTreeWidgetItem(tcp)
            #         tcpWindow.setText(0, 'Window：%s' % packet[TCP].window)
            #         tcpChksum = QtWidgets.QTreeWidgetItem(tcp)
            #         tcpChksum.setText(0, 'CheckSum：0x%x' % packet[TCP].chksum)
            #         tcpUrgptr = QtWidgets.QTreeWidgetItem(tcp)
            #         tcpUrgptr.setText(0, 'Urg ptr：%s' % packet[TCP].urgptr)
            #         tcpOptions = QtWidgets.QTreeWidgetItem(tcp)
            #         tcpOptions.setText(0, 'Options：%s' % packet[TCP].options)

                    # HTTP
                    # if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                    #     # HTTP Request
                    #     if packet.haslayer('HTTPRequest'):
                    #         http = QtWidgets.QTreeWidgetItem(self.treeWidget)
                    #         http.setText(0, 'HTTP Request')
                    #         if packet.sprintf("{HTTPRequest:%HTTPRequest.Method%}") != 'None':
                    #             httpMethod = QtWidgets.QTreeWidgetItem(http)
                    #             httpMethod.setText(0, 'Method：%s' % packet.sprintf("{HTTPRequest:%HTTPRequest.Method%}").strip("'"))
                    #         if packet.sprintf("{HTTPRequest:%HTTPRequest.Path%}") != 'None':
                    #             httpPath = QtWidgets.QTreeWidgetItem(http)
                    #             httpPath.setText(0, 'Path：%s' % packet.sprintf("{HTTPRequest:%HTTPRequest.Path%}").strip("'"))
                    #         if packet.sprintf("{HTTPRequest:%HTTPRequest.Http-Version%}") != 'None':
                    #             httpHttpVersion = QtWidgets.QTreeWidgetItem(http)
                    #             httpHttpVersion.setText(0, 'Http-Version：%s' % packet.sprintf("{HTTPRequest:%HTTPRequest.Http-Version%}").strip("'"))
                    #         if packet.sprintf("{HTTPRequest:%HTTPRequest.Host%}") != 'None':
                    #             httpHost = QtWidgets.QTreeWidgetItem(http)
                    #             httpHost.setText(0,'Host：%s' % packet.sprintf("{HTTPRequest:%HTTPRequest.Host%}").strip("'"))
                    #         if packet.sprintf("{HTTPRequest:%HTTPRequest.User-Agent%}") != 'None':
                    #             httpUserAgent = QtWidgets.QTreeWidgetItem(http)
                    #             httpUserAgent.setText(0, 'User-Agent：%s' % packet.sprintf("{HTTPRequest:%HTTPRequest.User-Agent%}").strip("'"))
                    #         if packet.sprintf("{HTTPRequest:%HTTPRequest.Accept%}") != 'None':
                    #             httpAccept = QtWidgets.QTreeWidgetItem(http)
                    #             httpAccept.setText(0, 'Accept：%s' % packet.sprintf("{HTTPRequest:%HTTPRequest.Accept%}").strip("'"))
                    #         if packet.sprintf("{HTTPRequest:%HTTPRequest.Accept-Language%}") != 'None':
                    #             httpAcceptLanguage = QtWidgets.QTreeWidgetItem(http)
                    #             httpAcceptLanguage.setText(0, 'Accept-Language：%s' % packet.sprintf("{HTTPRequest:%HTTPRequest.Accept-Language%}").strip("'"))
                    #         if packet.sprintf("{HTTPRequest:%HTTPRequest.Accept-Encoding%}") != 'None':
                    #             httpAcceptEncoding = QtWidgets.QTreeWidgetItem(http)
                    #             httpAcceptEncoding.setText(0, 'Accept-Encoding：%s' % packet.sprintf("{HTTPRequest:%HTTPRequest.Accept-Encoding%}").strip("'"))
                    #         if packet.sprintf("{HTTPRequest:%HTTPRequest.Accept-Charset%}") != 'None':
                    #             httpAcceptCharset = QtWidgets.QTreeWidgetItem(http)
                    #             httpAcceptCharset.setText(0, 'Accept-Charset：%s' % packet.sprintf("{HTTPRequest:%HTTPRequest.Accept-Charset%}").strip("'"))
                    #         if packet.sprintf("{HTTPRequest:%HTTPRequest.Referer%}") != 'None':
                    #             httpReferer = QtWidgets.QTreeWidgetItem(http)
                    #             httpReferer.setText(0, 'Referer：%s' % packet.sprintf("{HTTPRequest:%HTTPRequest.Referer%}").strip("'"))
                    #         if packet.sprintf("{HTTPRequest:%HTTPRequest.Authorization%}") != 'None':
                    #             httpAuthorization = QtWidgets.QTreeWidgetItem(http)
                    #             httpAuthorization.setText(0, 'Authorization：%s' % packet.sprintf("{HTTPRequest:%HTTPRequest.Authorization%}").strip("'"))
                    #         if packet.sprintf("{HTTPRequest:%HTTPRequest.Expect%}") != 'None':
                    #             httpExpect = QtWidgets.QTreeWidgetItem(http)
                    #             httpExpect.setText(0, 'Expect：%s' % packet.sprintf("{HTTPRequest:%HTTPRequest.Expect%}").strip("'"))
                    #         if packet.sprintf("{HTTPRequest:%HTTPRequest.From%}") != 'None':
                    #             httpFrom = QtWidgets.QTreeWidgetItem(http)
                    #             httpFrom.setText(0, 'From：%s' % packet.sprintf("{HTTPRequest:%HTTPRequest.From%}").strip("'"))
                    #         if packet.sprintf("{HTTPRequest:%HTTPRequest.If-Match%}") != 'None':
                    #             httpIfMatch = QtWidgets.QTreeWidgetItem(http)
                    #             httpIfMatch.setText(0, 'If-Match：%s' % packet.sprintf("{HTTPRequest:%HTTPRequest.If-Match%}").strip("'"))
                    #         if packet.sprintf("{HTTPRequest:%HTTPRequest.If-Modified-Since%}") != 'None':
                    #             httpIfModifiedSince = QtWidgets.QTreeWidgetItem(http)
                    #             httpIfModifiedSince.setText(0, 'If-Modified-Since：%s' % packet.sprintf("{HTTPRequest:%HTTPRequest.If-Modified-Since%}").strip("'"))
                    #         if packet.sprintf("{HTTPRequest:%HTTPRequest.If-None-Match%}") != 'None':
                    #             httpIfNoneMatch = QtWidgets.QTreeWidgetItem(http)
                    #             httpIfNoneMatch.setText(0, 'If-None-Match：%s' % packet.sprintf("{HTTPRequest:%HTTPRequest.If-None-Match%}").strip("'"))
                    #         if packet.sprintf("{HTTPRequest:%HTTPRequest.If-Range%}") != 'None':
                    #             httpIfRange = QtWidgets.QTreeWidgetItem(http)
                    #             httpIfRange.setText(0, 'If-Range：%s' % packet.sprintf("{HTTPRequest:%HTTPRequest.If-Range%}").strip("'"))
                    #         if packet.sprintf("{HTTPRequest:%HTTPRequest.If-Unmodified-Since%}") != 'None':
                    #             httpIfUnmodifiedSince = QtWidgets.QTreeWidgetItem(http)
                    #             httpIfUnmodifiedSince.setText(0, 'If-Unmodified-Since：%s' % packet.sprintf("{HTTPRequest:%HTTPRequest.If-Unmodified-Since%}").strip("'"))
                    #         if packet.sprintf("{HTTPRequest:%HTTPRequest.Max-Forwards%}") != 'None':
                    #             httpMaxForwards = QtWidgets.QTreeWidgetItem(http)
                    #             httpMaxForwards.setText(0, 'Max-Forwards：%s' % packet.sprintf("{HTTPRequest:%HTTPRequest.Max-Forwards%}").strip("'"))
                    #         if packet.sprintf("{HTTPRequest:%HTTPRequest.Proxy-Authorization%}") != 'None':
                    #             httpProxyAuthorization = QtWidgets.QTreeWidgetItem(http)
                    #             httpProxyAuthorization.setText(0, 'Proxy-Authorization：%s' % packet.sprintf("{HTTPRequest:%HTTPRequest.Proxy-Authorization%}").strip("'"))
                    #         if packet.sprintf("{HTTPRequest:%HTTPRequest.Range%}") != 'None':
                    #             httpRange = QtWidgets.QTreeWidgetItem(http)
                    #             httpRange.setText(0, 'Range：%s' % packet.sprintf("{HTTPRequest:%HTTPRequest.Range%}").strip("'"))
                    #         if packet.sprintf("{HTTPRequest:%HTTPRequest.TE%}") != 'None':
                    #             httpTE = QtWidgets.QTreeWidgetItem(http)
                    #             httpTE.setText(0, 'TE：%s' % packet.sprintf("{HTTPRequest:%HTTPRequest.TE%}").strip("'"))
                    #         if packet.sprintf("{HTTPRequest:%HTTPRequest.Cache-Control%}") != 'None':
                    #             httpCacheControl = QtWidgets.QTreeWidgetItem(http)
                    #             httpCacheControl.setText(0, 'Cache-Control：%s' % packet.sprintf("{HTTPRequest:%HTTPRequest.Cache-Control%}").strip("'"))
                    #         if packet.sprintf("{HTTPRequest:%HTTPRequest.Connection%}") != 'None':
                    #             httpConnection = QtWidgets.QTreeWidgetItem(http)
                    #             httpConnection.setText(0, 'Connection：%s' % packet.sprintf("{HTTPRequest:%HTTPRequest.Connection%}").strip("'"))
                    #         if packet.sprintf("{HTTPRequest:%HTTPRequest.Date%}") != 'None':
                    #             httpDate = QtWidgets.QTreeWidgetItem(http)
                    #             httpDate.setText(0,'Date：%s' % packet.sprintf("{HTTPRequest:%HTTPRequest.Date%}").strip("'"))
                    #         if packet.sprintf("{HTTPRequest:%HTTPRequest.Pragma%}") != 'None':
                    #             httpPragma = QtWidgets.QTreeWidgetItem(http)
                    #             httpPragma.setText(0, 'Pragma：%s' % packet.sprintf("{HTTPRequest:%HTTPRequest.Pragma%}").strip("'"))
                    #         if packet.sprintf("{HTTPRequest:%HTTPRequest.Trailer%}") != 'None':
                    #             httpTrailer = QtWidgets.QTreeWidgetItem(http)
                    #             httpTrailer.setText(0, 'Trailer：%s' % packet.sprintf("{HTTPRequest:%HTTPRequest.Trailer%}").strip("'"))
                    #         if packet.sprintf("{HTTPRequest:%HTTPRequest.Transfer-Encoding%}") != 'None':
                    #             httpTransferEncoding = QtWidgets.QTreeWidgetItem(http)
                    #             httpTransferEncoding.setText(0, 'Transfer-Encoding：%s' % packet.sprintf("{HTTPRequest:%HTTPRequest.Transfer-Encoding%}").strip("'"))
                    #         if packet.sprintf("{HTTPRequest:%HTTPRequest.Upgrade%}") != 'None':
                    #             httpUpgrade = QtWidgets.QTreeWidgetItem(http)
                    #             httpUpgrade.setText(0, 'Upgrade：%s' % packet.sprintf("{HTTPRequest:%HTTPRequest.Upgrade%}").strip("'"))
                    #         if packet.sprintf("{HTTPRequest:%HTTPRequest.Via%}") != 'None':
                    #             httpVia = QtWidgets.QTreeWidgetItem(http)
                    #             httpVia.setText(0, 'Via：%s' % packet.sprintf("{HTTPRequest:%HTTPRequest.Via%}").strip("'"))
                    #         if packet.sprintf("{HTTPRequest:%HTTPRequest.Warning%}") != 'None':
                    #             httpWarning = QtWidgets.QTreeWidgetItem(http)
                    #             httpWarning.setText(0, 'Warning：%s' % packet.sprintf("{HTTPRequest:%HTTPRequest.Warning%}").strip("'"))
                    #         if packet.sprintf("{HTTPRequest:%HTTPRequest.Keep-Alive%}") != 'None':
                    #             httpKeepAlive = QtWidgets.QTreeWidgetItem(http)
                    #             httpKeepAlive.setText(0, 'Keep-Alive：%s' % packet.sprintf("{HTTPRequest:%HTTPRequest.Keep-Alive%}").strip("'"))
                    #         if packet.sprintf("{HTTPRequest:%HTTPRequest.Allow%}") != 'None':
                    #             httpAllow = QtWidgets.QTreeWidgetItem(http)
                    #             httpAllow.setText(0, 'Allow：%s' % packet.sprintf("{HTTPRequest:%HTTPRequest.Allow%}").strip("'"))
                    #         if packet.sprintf("{HTTPRequest:%HTTPRequest.Content-Encoding%}") != 'None':
                    #             httpContentEncoding = QtWidgets.QTreeWidgetItem(http)
                    #             httpContentEncoding.setText(0, 'Content-Encoding：%s' % packet.sprintf("{HTTPRequest:%HTTPRequest.Content-Encoding%}").strip("'"))
                    #         if packet.sprintf("{HTTPRequest:%HTTPRequest.Content-Language%}") != 'None':
                    #             httpContentLanguage = QtWidgets.QTreeWidgetItem(http)
                    #             httpContentLanguage.setText(0, 'Content-Language：%s' % packet.sprintf("{HTTPRequest:%HTTPRequest.Content-Language%}").strip("'"))
                    #         if packet.sprintf("{HTTPRequest:%HTTPRequest.Content-Length%}") != 'None':
                    #             httpContentLength = QtWidgets.QTreeWidgetItem(http)
                    #             httpContentLength.setText(0, 'Content-Length：%s' % packet.sprintf("{HTTPRequest:%HTTPRequest.Content-Length%}").strip("'"))
                    #         if packet.sprintf("{HTTPRequest:%HTTPRequest.Content-Location%}") != 'None':
                    #             httpContentLocation = QtWidgets.QTreeWidgetItem(http)
                    #             httpContentLocation.setText(0, 'Content-Location：%s' % packet.sprintf("{HTTPRequest:%HTTPRequest.Content-Location%}").strip("'"))
                    #         if packet.sprintf("{HTTPRequest:%HTTPRequest.Content-MD5%}") != 'None':
                    #             httpContentMD5 = QtWidgets.QTreeWidgetItem(http)
                    #             httpContentMD5.setText(0, 'Content-MD5：%s' % packet.sprintf("{HTTPRequest:%HTTPRequest.Content-MD5%}").strip("'"))
                    #         if packet.sprintf("{HTTPRequest:%HTTPRequest.Content-Range%}") != 'None':
                    #             httpContentRange = QtWidgets.QTreeWidgetItem(http)
                    #             httpContentRange.setText(0, 'Content-Range：%s' % packet.sprintf("{HTTPRequest:%HTTPRequest.Content-Range%}").strip("'"))
                    #         if packet.sprintf("{HTTPRequest:%HTTPRequest.Content-Type%}") != 'None':
                    #             httpContentType = QtWidgets.QTreeWidgetItem(http)
                    #             httpContentType.setText(0, 'Content-Type：%s' % packet.sprintf("{HTTPRequest:%HTTPRequest.Content-Type%}").strip("'"))
                    #         if packet.sprintf("{HTTPRequest:%HTTPRequest.Expires%}") != 'None':
                    #             httpExpires = QtWidgets.QTreeWidgetItem(http)
                    #             httpExpires.setText(0, 'Expires：%s' % packet.sprintf("{HTTPRequest:%HTTPRequest.Expires%}").strip("'"))
                    #         if packet.sprintf("{HTTPRequest:%HTTPRequest.Last-Modified%}") != 'None':
                    #             httpLastModified = QtWidgets.QTreeWidgetItem(http)
                    #             httpLastModified.setText(0, 'Last-Modified：%s' % packet.sprintf("{HTTPRequest:%HTTPRequest.Last-Modified%}").strip("'"))
                    #         if packet.sprintf("{HTTPRequest:%HTTPRequest.Cookie%}") != 'None':
                    #             httpCookie = QtWidgets.QTreeWidgetItem(http)
                    #             httpCookie.setText(0, 'Cookie：%s' % packet.sprintf("{HTTPRequest:%HTTPRequest.Cookie%}").strip("'"))

                        # HTTP Response
                        # if packet.haslayer('HTTPResponse'):
                        #     http = QtWidgets.QTreeWidgetItem(self.treeWidget)
                        #     http.setText(0, 'HTTP Response')
                        #     if packet.sprintf("{HTTPResponse:%HTTPResponse.Status-Line%}") != 'None':
                        #         httpStatusLine = QtWidgets.QTreeWidgetItem(http)
                        #         httpStatusLine.setText(0, 'Status-Line：%s' % packet.sprintf("{HTTPResponse:%HTTPResponse.Status-Line%}").strip("'"))
                        #     if packet.sprintf("{HTTPResponse:%HTTPResponse.Accept-Ranges%}") != 'None':
                        #         httpAcceptRanges = QtWidgets.QTreeWidgetItem(http)
                        #         httpAcceptRanges.setText(0, 'Accept-Ranges：%s' % packet.sprintf("{HTTPResponse:%HTTPResponse.Accept-Ranges%}").strip("'"))
                        #     if packet.sprintf("{HTTPResponse:%HTTPResponse.Age%}") != 'None':
                        #         httpAge = QtWidgets.QTreeWidgetItem(http)
                        #         httpAge.setText(0, 'Age：%s' % packet.sprintf("{HTTPResponse:%HTTPResponse.Age%}").strip("'"))
                        #     if packet.sprintf("{HTTPResponse:%HTTPResponse.E-Tag%}") != 'None':
                        #         httpETag = QtWidgets.QTreeWidgetItem(http)
                        #         httpETag.setText(0, 'E-Tag：%s' % packet.sprintf("{HTTPResponse:%HTTPResponse.E-Tag%}").strip("'"))
                        #     if packet.sprintf("{HTTPResponse:%HTTPResponse.Location%}") != 'None':
                        #         httpLocation = QtWidgets.QTreeWidgetItem(http)
                        #         httpLocation.setText(0, 'Location：%s' % packet.sprintf("{HTTPResponse:%HTTPResponse.Location%}").strip("'"))
                        #     if packet.sprintf("{HTTPResponse:%HTTPResponse.Proxy-Authenticate%}") != 'None':
                        #         httpProxyAuthenticate = QtWidgets.QTreeWidgetItem(http)
                        #         httpProxyAuthenticate.setText(0, 'Proxy-Authenticate：%s' % packet.sprintf("{HTTPResponse:%HTTPResponse.Proxy-Authenticate%}").strip("'"))
                        #     if packet.sprintf("{HTTPResponse:%HTTPResponse.Retry-After%}") != 'None':
                        #         httpRetryAfter = QtWidgets.QTreeWidgetItem(http)
                        #         httpRetryAfter.setText(0, 'Retry-After：%s' % packet.sprintf("{HTTPResponse:%HTTPResponse.Retry-After%}").strip("'"))
                        #     if packet.sprintf("{HTTPResponse:%HTTPResponse.Server%}") != 'None':
                        #         httpServer = QtWidgets.QTreeWidgetItem(http)
                        #         httpServer.setText(0, 'Server：%s' % packet.sprintf("{HTTPResponse:%HTTPResponse.Server%}").strip("'"))
                        #     if packet.sprintf("{HTTPResponse:%HTTPResponse.Vary%}") != 'None':
                        #         httpVary = QtWidgets.QTreeWidgetItem(http)
                        #         httpVary.setText(0, 'Vary：%s' % packet.sprintf("{HTTPResponse:%HTTPResponse.Vary%}").strip("'"))
                        #     if packet.sprintf("{HTTPResponse:%HTTPResponse.WWW-Authenticate%}") != 'None':
                        #         httpWWWAuthenticate = QtWidgets.QTreeWidgetItem(http)
                        #         httpWWWAuthenticate.setText(0, 'WWW-Authenticate：%s' % packet.sprintf("{HTTPResponse:%HTTPResponse.WWW-Authenticate%}").strip("'"))
                        #     if packet.sprintf("{HTTPResponse:%HTTPResponse.Cache-Control%}") != 'None':
                        #         httpCacheControl = QtWidgets.QTreeWidgetItem(http)
                        #         httpCacheControl.setText(0, 'Cache-Control：%s' % packet.sprintf("{HTTPResponse:%HTTPResponse.Cache-Control%}").strip("'"))
                        #     if packet.sprintf("{HTTPResponse:%HTTPResponse.Connection%}") != 'None':
                        #         httpConnection = QtWidgets.QTreeWidgetItem(http)
                        #         httpConnection.setText(0, 'Connection：%s' % packet.sprintf("{HTTPResponse:%HTTPResponse.Connection%}").strip("'"))
                        #     if packet.sprintf("{HTTPResponse:%HTTPResponse.Date%}") != 'None':
                        #         httpDate = QtWidgets.QTreeWidgetItem(http)
                        #         httpDate.setText(0, 'Date：%s' % packet.sprintf("{HTTPResponse:%HTTPResponse.Date%}").strip("'"))
                        #     if packet.sprintf("{HTTPResponse:%HTTPResponse.Pragma%}") != 'None':
                        #         httpPragma = QtWidgets.QTreeWidgetItem(http)
                        #         httpPragma.setText(0, 'Pragma：%s' % packet.sprintf("{HTTPResponse:%HTTPResponse.Pragma%}").strip("'"))
                        #     if packet.sprintf("{HTTPResponse:%HTTPResponse.Trailer%}") != 'None':
                        #         httpTrailer = QtWidgets.QTreeWidgetItem(http)
                        #         httpTrailer.setText(0, 'Trailer：%s' % packet.sprintf("{HTTPResponse:%HTTPResponse.Trailer%}").strip("'"))
                        #     if packet.sprintf("{HTTPResponse:%HTTPResponse.Transfer-Encoding%}") != 'None':
                        #         httpTransferEncoding = QtWidgets.QTreeWidgetItem(http)
                        #         httpTransferEncoding.setText(0, 'Transfer-Encoding：%s' % packet.sprintf("{HTTPResponse:%HTTPResponse.Transfer-Encoding%}").strip("'"))
                        #     if packet.sprintf("{HTTPResponse:%HTTPResponse.Upgrade%}") != 'None':
                        #         httpUpgrade = QtWidgets.QTreeWidgetItem(http)
                        #         httpUpgrade.setText(0, 'Upgrade：%s' % packet.sprintf("{HTTPResponse:%HTTPResponse.Upgrade%}").strip("'"))
                        #     if packet.sprintf("{HTTPResponse:%HTTPResponse.Via%}") != 'None':
                        #         httpVia = QtWidgets.QTreeWidgetItem(http)
                        #         httpVia.setText(0, 'Via：%s' % packet.sprintf("{HTTPResponse:%HTTPResponse.Via%}").strip("'"))
                        #     if packet.sprintf("{HTTPResponse:%HTTPResponse.Warning%}") != 'None':
                        #         httpWarning = QtWidgets.QTreeWidgetItem(http)
                        #         httpWarning.setText(0, 'Warning：%s' % packet.sprintf("{HTTPResponse:%HTTPResponse.Warning%}").strip("'"))
                        #     if packet.sprintf("{HTTPResponse:%HTTPResponse.Keep-Alive%}") != 'None':
                        #         httpKeepAlive = QtWidgets.QTreeWidgetItem(http)
                        #         httpKeepAlive.setText(0, 'Keep-Alive：%s' % packet.sprintf("{HTTPResponse:%HTTPResponse.Keep-Alive%}").strip("'"))
                        #     if packet.sprintf("{HTTPResponse:%HTTPResponse.Allow%}") != 'None':
                        #         httpAllow = QtWidgets.QTreeWidgetItem(http)
                        #         httpAllow.setText(0, 'Allow：%s' % packet.sprintf("{HTTPResponse:%HTTPResponse.Allow%}").strip("'"))
                        #     if packet.sprintf("{HTTPResponse:%HTTPResponse.Content-Encoding%}") != 'None':
                        #         httpContentEncoding = QtWidgets.QTreeWidgetItem(http)
                        #         httpContentEncoding.setText(0, 'Content-Encoding：%s' % packet.sprintf("{HTTPResponse:%HTTPResponse.Content-Encoding%}").strip("'"))
                        #     if packet.sprintf("{HTTPResponse:%HTTPResponse.Content-Language%}") != 'None':
                        #         httpContentLanguage = QtWidgets.QTreeWidgetItem(http)
                        #         httpContentLanguage.setText(0, 'Content-Language：%s' % packet.sprintf("{HTTPResponse:%HTTPResponse.Content-Language%}").strip("'"))
                        #     if packet.sprintf("{HTTPResponse:%HTTPResponse.Content-Length%}") != 'None':
                        #         httpContentLength = QtWidgets.QTreeWidgetItem(http)
                        #         httpContentLength.setText(0, 'Content-Length：%s' % packet.sprintf("{HTTPResponse:%HTTPResponse.Content-Length%}").strip("'"))
                        #     if packet.sprintf("{HTTPResponse:%HTTPResponse.Content-Location%}") != 'None':
                        #         httpContentLocation = QtWidgets.QTreeWidgetItem(http)
                        #         httpContentLocation.setText(0, 'Content-Location：%s' % packet.sprintf("{HTTPResponse:%HTTPResponse.Content-Location%}").strip("'"))
                        #     if packet.sprintf("{HTTPResponse:%HTTPResponse.Content-MD5%}") != 'None':
                        #         httpContentMD5 = QtWidgets.QTreeWidgetItem(http)
                        #         httpContentMD5.setText(0, 'Content-MD5：%s' % packet.sprintf("{HTTPResponse:%HTTPResponse.Content-MD5%}").strip("'"))
                        #     if packet.sprintf("{HTTPResponse:%HTTPResponse.Content-Range%}") != 'None':
                        #         httpContentRange = QtWidgets.QTreeWidgetItem(http)
                        #         httpContentRange.setText(0, 'Content-Range：%s' % packet.sprintf("{HTTPResponse:%HTTPResponse.Content-Range%}").strip("'"))
                        #     if packet.sprintf("{HTTPResponse:%HTTPResponse.Content-Type%}") != 'None':
                        #         httpContentType = QtWidgets.QTreeWidgetItem(http)
                        #         httpContentType.setText(0, 'Content-Type：%s' % packet.sprintf("{HTTPResponse:%HTTPResponse.Content-Type%}").strip("'"))
                        #     if packet.sprintf("{HTTPResponse:%HTTPResponse.Expires%}") != 'None':
                        #         httpExpires = QtWidgets.QTreeWidgetItem(http)
                        #         httpExpires.setText(0, 'Expires：%s' % packet.sprintf("{HTTPResponse:%HTTPResponse.Expires%}").strip("'"))
                        #     if packet.sprintf("{HTTPResponse:%HTTPResponse.Last-Modified%}") != 'None':
                        #         httpLastModified = QtWidgets.QTreeWidgetItem(http)
                        #         httpLastModified.setText(0, 'Last-Modified：%s' % packet.sprintf("{HTTPResponse:%HTTPResponse.Last-Modified%}").strip("'"))

            # UDP
            # elif packet[IP].proto == 17:
            #     IPv4Proto = QtWidgets.QTreeWidgetItem(IPv4)
            #     IPv4Proto.setText(0, '프로토콜(proto)：UDP(17)')
            #     udp = QtWidgets.QTreeWidgetItem(self.treeWidget)
            #     udp.setText(0, 'UDP，출발 포트(sport)：%s，도착 포트(dport)：%s' % (packet[UDP].sport, packet[UDP].dport))
            #     udpSport = QtWidgets.QTreeWidgetItem(udp)
            #     udpSport.setText(0, '출발 포트(sport)：%s' % packet[UDP].sport)
            #     udpDport = QtWidgets.QTreeWidgetItem(udp)
            #     udpDport.setText(0, '도착 포트(dport)：%s' % packet[UDP].dport)
            #     udpLen = QtWidgets.QTreeWidgetItem(udp)
            #     udpLen.setText(0, '길이(Len)：%s' % packet[UDP].len)
            #     udpChksum = QtWidgets.QTreeWidgetItem(udp)
            #     udpChksum.setText(0, 'CheckSum：0x%x' % packet[UDP].chksum)
                # DNS
                # if packet.haslayer('DNS'):
                #     pass
                    # nds = QtWidgets.QTreeWidgetItem(self.treeWidget)
                    # nds.setText(0,'DNS')
            # ICMP
            # elif packet[IP].proto == 1:
            #     IPv4Proto = QtWidgets.QTreeWidgetItem(IPv4)
            #     IPv4Proto.setText(0, '프로토콜(proto)：ICMP(1)')
            #     icmp = QtWidgets.QTreeWidgetItem(self.treeWidget)
            #     icmp.setText(0, 'ICMP')
            #     icmpType = QtWidgets.QTreeWidgetItem(icmp)
            #     if packet[ICMP].type == 8:
            #         icmpType.setText(0, '유형(type)：%s (Echo (ping) request)' % packet[ICMP].type)
            #     elif packet[ICMP].type == 0:
            #         icmpType.setText(0, '유형(type)：%s (Echo (ping) reply)' % packet[ICMP].type)
            #     else:
            #         icmpType.setText(0, '유형(type)：%s' % packet[ICMP].type)
            #     icmpCode = QtWidgets.QTreeWidgetItem(icmp)
            #     icmpCode.setText(0, 'Code：%s' % packet[ICMP].code)
            #     icmpChksum = QtWidgets.QTreeWidgetItem(icmp)
            #     icmpChksum.setText(0, 'CheckSum：0x%x' % packet[ICMP].chksum)

                # IGMP
            # elif packet[IP].proto == 2:
            #     IPv4Proto = QtWidgets.QTreeWidgetItem(IPv4)
            #     IPv4Proto.setText(0, '프로토콜(proto)：IGMP(2)')
            #
            #     igmp = QtWidgets.QTreeWidgetItem(self.treeWidget)
            #     igmp.setText(0, 'IGMP')
            #     igmpCopy_flag = QtWidgets.QTreeWidgetItem(igmp)
            #     igmpCopy_flag.setText(0, 'copy_flag：%s' % packet[IPOption_Router_Alert].copy_flag)
            #     igmpOptclass = QtWidgets.QTreeWidgetItem(igmp)
            #     igmpOptclass.setText(0, 'optclass：%s' % packet[IPOption_Router_Alert].optclass)
            #     igmpOption = QtWidgets.QTreeWidgetItem(igmp)
            #     igmpOption.setText(0, 'option：%s' % packet[IPOption_Router_Alert].option)
            #     igmpLength = QtWidgets.QTreeWidgetItem(igmp)
            #     igmpLength.setText(0, 'length：%s' % packet[IPOption_Router_Alert].length)
            #     igmpAlert = QtWidgets.QTreeWidgetItem(igmp)
            #     igmpAlert.setText(0, 'alert：%s' % packet[IPOption_Router_Alert].alert)
            # else:
            #     IPv4Proto = QtWidgets.QTreeWidgetItem(IPv4)
            #     IPv4Proto.setText(0, '프로토콜(proto)：%s' % packet[IP].proto)

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
            # old = sys.stdout  # 将当前系统输出储存到临时变量
            # sys.stdout = f  # 输出重定向到文件
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
