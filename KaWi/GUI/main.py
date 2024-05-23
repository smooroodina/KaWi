import os, sys
from PyQt5.QtWidgets import *
from PyQt5 import uic

def resource_path(relative_path):
    base_path = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_path, relative_path)

form = resource_path('Sniffer.ui')
form_Sniffer = uic.loadUiType(form)[0]

form_second = resource_path('Spoofing.ui')
form_Spoofing = uic.loadUiType(form_second)[0]

form_third = resource_path('KRACK.ui')
form_KRACK = uic.loadUiType(form_third)[0]

class SniffingWindow(QMainWindow, form_Sniffer):
    def __init__(self):
        super().__init__()
        self.setupUi(self)
        self.initUI()
        self.setWindowTitle("Sniffing Window")
        self.show()

    def initUI(self):
        self.chk_monitorMode.stateChanged.connect(self.handleButtonClick)
        self.toggleButton.clicked.connect(self.handleButtonClick)
        self.setButton.clicked.connect(self.btn_to_SpoofingWindow)

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

    def btn_to_SpoofingWindow(self):
        self.hide()
        self.SpoofingWindow = SpoofingWindow(self)
        self.SpoofingWindow.show()

class SpoofingWindow(QMainWindow, form_Spoofing):
    def __init__(self, parent=SniffingWindow):
        super(SpoofingWindow, self).__init__(parent)
        self.setupUi(self)
        self.setWindowTitle("Spoofing Window")
        self.toggleButton.clicked.connect(self.handleButtonClick)
        self.KRACKButton.clicked.connect(self.btn_to_KRACKWindow)

    def handleButtonClick(self):
        sender = self.sender()  # 이벤트를 발생시킨 위젯 확인
        if sender.text() == "Start":
            QMessageBox.information(self, "Start", "시작 버튼 선택")
            sender.setText("Stop")
        else:
            QMessageBox.information(self, "Stop", "정지 버튼 선택")
            sender.setText("Start")

    def btn_to_KRACKWindow(self):
        self.hide()
        self.KRACKWindow = KRACKWindow(self)
        self.KRACKWindow.show()

class KRACKWindow(QMainWindow, form_KRACK):
    def __init__(self, parent=SpoofingWindow):
        super(KRACKWindow, self).__init__(parent)
        self.setupUi(self)
        self.setWindowTitle("KRACK Window")
        self.toggleButton.clicked.connect(self.handleButtonClick)

    def handleButtonClick(self):
        sender = self.sender()  # 이벤트를 발생시킨 위젯 확인
        if sender.text() == "Start":
            QMessageBox.information(self, "Start", "시작 버튼 선택")
            sender.setText("Stop")
        else:
            QMessageBox.information(self, "Stop", "정지 버튼 선택")
            sender.setText("Start")

        QMessageBox.information(self, "Radio", f'{self.whichRadioChecked()}')

    def whichRadioChecked(self):
        if self.radio_Replay_Broadcast.isChecked():
            return 1
        if self.radio_Test_GTK.isChecked():
            return 2
        elif self.radio_Test_KRACK.isChecked():
            return 3
        elif self.radio_KRACK_Attack.isChecked():
            return 4
        elif self.radio_Entire.isChecked():
            return 5

if __name__ == "__main__":
    app = QApplication(sys.argv)
    myWindow = SniffingWindow()
    sys.exit(app.exec_())
