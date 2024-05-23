import os, sys
from PyQt5.QtWidgets import *
from PyQt5 import uic

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
        self.Spoof_toggleButton.clicked.connect(self.handleButtonClick)
        self.Spoof_KRACKButton.clicked.connect(self.move_to_next_tab)
        self.KRACK_toggleButton.clicked.connect(self.handleButtonClick)

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

            if sender.objectName() == "KRACK_toggleButton" and sender.text() == "Stop":
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

    def move_to_next_tab(self):
        current_index = self.tabs.currentIndex()
        next_index = (current_index + 1) % self.tabs.count()
        self.tabs.setCurrentIndex(next_index)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    myWindow = MainWindow()
    sys.exit(app.exec_())
