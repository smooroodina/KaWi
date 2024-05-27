# 기능별로 모듈을 구분해 개발하기 전에 이 파일에서 작성하여 잘 작동하는지 실행시켜 봅니다.
import os
import sys
from PyQt5 import QtCore, QtGui, QtWidgets

sys.path.append(os.path.dirname(os.path.abspath(__file__)) + '\\scapy')
from scapy.all import *     # noqa: E402
