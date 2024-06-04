import os
import sys
import threading
import subprocess
import logging
from contextlib import redirect_stdout


logging.basicConfig(filename=os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'log', 'sniff.log'),
                    level=logging.DEBUG,
                    format='%(asctime)s [%(levelname)s]%(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'scapy'))
from scapy.all import *  # noqa: E402
from scapy.consts import LINUX

iface_managed = None
iface_monitor = None

# Execute netsh command to connect to a Wi-Fi without a password you've already connected to.
#   [Input] Network ssid or bssid, Network interface to use
#   [Output] Success or not
def simple_connect_to_wifi(ssid, iface=None):
    if iface is None:
        iface = iface_managed
    command = 'netsh wlan connect ssid="{}" name="{}" interface="{}"'.format(ssid, ssid, iface.name)
    print()
    subprocess.run(command, shell=True)

    return True     # But this is a connection request success and does not guarantee the establishment of a connection.
