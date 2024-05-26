import os
import sys
import logging

logging.basicConfig(filename='../log/sniff.log',
                    level=logging.DEBUG,
                    format='%(asctime)s [%(levelname)s]%(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'scapy'))
from scapy.all import *  # noqa: E402

class Network:
    def __init__(self, ssid:str, bssid:str, channel:int, crypto:set[str]):
        self.ssid = ssid
        self.bssid = bssid
        self.channel = channel
        self.crypto = crypto
        self.subnet = None
        self.gateway = None

    def __str__(self):
        return '[Network info] ssid:{}  bssid:{}  channel:{}  crypto:{}  subnet:{}  gateway:{}'.format(self.ssid, self.bssid, self.channel, self.crypto, self.subnet, self.gateway)

class Host:
    def __init__(self, bssid:str, MAC:str, IP:str):
        self.bssid = bssid
        self.MAC = MAC
        self.IP = IP



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


def kawi_sniff():
    ap_list = []

    # Callback function that executes with each packet sniffed.
    #   [Input] a packet
    #   [Output] none
    def packet_handler(packet):
        # if u want to print summary information of the packet: print(packet.summary())
        # todo:
        #  - 주변 AP 및 Client MAC 주소 불러오기. 어떨게?
        #      1. Management Frame(Beacon Frame, Probe Request/Response 등)
        if packet.type == 0 and packet.subtype == 8:
            if packet.addr2 not in ap_list:
                ap_list.append(packet.addr2)
                print("AP MAC: %s with SSID: %s " % (packet.addr2, packet.info))

    iface_list = lookup_iface()
    # select one, set to conf.iface
    # ...
    conf.iface = next((i for i in iface_list if i.description == '802.11n USB Wireless LAN Card'), None)
    if conf.iface is None:
        logging.error("Network interface is not recognized: 802.11n USB Wireless LAN Card")
        return
    # can choose whether to sniff in monitor mode or not.
    monitor = True
    # params for sniff(): scapy/scapy/sendrecv.py - class AsyncSniffer - def _run(...) 참고.
    # iface 명시하지 않으면 자동으로 conf.iface의 인터페이스가 선택됨
    conf.iface.setmonitor(False)
    sniff(prn=packet_handler, monitor=monitor)


# Change the channel of the target network interface. (Only works in monitor mode.)
#   [Input] Channel number, Target interface
#   [Output] Success or failure
def switch_channel(num: int, iface=conf.iface) -> bool:
    if not iface.ismonitor():
        print("Cannot change channel. First you need to switch your iface to monitor mode.")
        return False
    else:
        iface.setchannel(num)
        return True  # But it's still possible that it failed... (responsibility of scapy)

# Scan access points while switching channels in the 2.4GHz and 5GHz bands.
#   [Input] Channel list for scanning, Frequency('2.4ghz' or '5ghz'), Passive/Active scan, Network interface to use
#   [Output] List of connectable networks (ssid, bssid, channel, crypto)
def scan_AP(channels: list[int] = None, frequency: str = None, active: bool = False, iface=conf.iface) -> list[Network]:
    wifi_2_4_channels = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]
    wifi_5_channels = [36, 40, 44, 48, 149, 153, 157, 161]  # in KOREA
    network_list = []
    current_channel = 0

    # Callback function that executes with each packet sniffed.
    def handle_scan_AP(packet):
        try:
            # Passive Scan
            if packet.haslayer(Dot11Beacon):  # Beacon Frame
                netstats = packet[Dot11Beacon].network_stats()
                if ('channel' in netstats and netstats['channel'] == current_channel  # Discard frames from other channels
                        and packet.addr3 not in [network.bssid for network in network_list]):
                    network_list.append(Network(
                        netstats['ssid'],
                        packet.addr3,
                        netstats['channel'],
                        netstats['crypto']
                    ))
                    print(network_list[-1])
            '''
            if active:  # Active Scan
                if packet.type == 0 and (packet.subtype == 4 or packet.subtype == 5):    # Probe Request/Response Frame
                    ...
                    print('Sorry, active scanning is currently not supported.')
            '''
        except (KeyError, TypeError) as e:  # Probably a malformed packet
            ...

    if channels is None:
        if frequency is None:
            channels = wifi_2_4_channels + wifi_5_channels
        elif frequency.lower() == '2.4ghz':
            channels = wifi_2_4_channels
        elif frequency.lower() == '5ghz':
            channels = wifi_5_channels

    print('Start passive scan')

    iface.setmonitor(True)
    for n in channels:
        # Sequential channel switching - Stays for 1 second on each channel
        current_channel = n
        print('Current channel: %d' % n)
        switch_channel(n, iface)
        sniff(iface=iface, monitor=True, timeout=1, prn=handle_scan_AP, store=0)
    iface.setmonitor(False)
    return network_list


# Scan the MAC addresses of host devices from probe requests
def scan_host_MAC(network: Network, iface=conf.iface) -> list[dict]:
    host_MAC_list = []
    # Callback function that executes with each packet sniffed.
    def handle_scan_host_MAC(packet):
        try:
            ...
        except (KeyError, TypeError) as e:  # Probably a malformed packet
            ...
    return host_MAC_list

# Scan client devices connected to a specific network.
#   [Input] Target network, Network interface to use
#   [Output] Information list of client devices ( )
def scan_host(network: Network, iface=conf.iface) -> list[Host]:
    # Callback function that executes with each packet sniffed.
    def handle_scan_host(packet):
        try:
            # Passive Scan
            if packet.haslayer(Dot11):  # Beacon Frame
                netstats = packet[Dot11Beacon].network_stats()
                if ('channel' in netstats and netstats[
                    'channel'] == current_channel  # Discard frames from other channels
                        and packet.addr3 not in [ap['bssid'] for ap in network_list]):
                    network_list.append(Network(
                        netstats['ssid'],
                        packet.addr3,
                        netstats['channel'],
                        netstats['crypto']
                    ))
                    print(network_list[-1])
            '''
            if active:  # Active Scan
                if packet.type == 0 and (packet.subtype == 4 or packet.subtype == 5):    # Probe Request/Response Frame
                    ...
                    print('Sorry, active scanning is currently not supported.')
            '''
        except (KeyError, TypeError) as e:  # Probably a malformed packet
            ...
    client_mac_list = scan_host_MAC()
    switch_channel(network.channel, iface)
    iface.setmonitor(True)
    sniff(iface=iface, monitor=True, timeout=10, prn=handle_scan_host, store=0)
    iface.setmonitor(False)


if __name__ == '__main__':
    print(sys.argv)
    iface_list = lookup_iface()
    scan_AP(frequency='2.4ghz', iface=next((i for i in iface_list if i.description == '802.11n USB Wireless LAN Card'), None))
