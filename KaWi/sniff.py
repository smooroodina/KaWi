import os
import sys
import logging
logging.basicConfig(filename='../log/sniff.log',
                    level=logging.DEBUG,
                    format='%(asctime)s [%(levelname)s]%(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'scapy'))
from scapy.all import *     # noqa: E402



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
        ## todo:
        ##  - 주변 AP 및 Client MAC 주소 불러오기. 어떨게?
        ##      1. Management Frame(Beacon Frame, Probe Request/Response 등)
        if packet.type == 0 and packet.subtype == 8:
            if packet.addr2 not in ap_list:
                ap_list.append(packet.addr2)
                print("AP MAC: %s with SSID: %s " % (packet.addr2, packet.info))

    # example code from https://charlesreid1.com/wiki/Scapy/AP_Scanner
    aps = {}
    def sniffAP(p):
        if ((p.haslayer(Dot11Beacon) or p.haslayer(Dot11ProbeResp))
                and not p[Dot11].addr3 in aps):
            ssid = p[Dot11Elt].info
            bssid = p[Dot11].addr3
            channel = int(ord(p[Dot11Elt:3].info))
            capability = p.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}\
                    {Dot11ProbeResp:%Dot11ProbeResp.cap%}")

            # Check for encrypted networks
            if re.search("privacy", capability):
                enc = 'Y'
            else:
                enc = 'N'

            # Save discovered AP
            aps[p[Dot11].addr3] = enc

            # Display discovered AP
            print
            "%02d  %s  %s %s" % (int(channel), enc, bssid, ssid)
            # Get my network interface name list

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
def switch_channel(n:int, iface=conf.iface) -> bool:
    if not iface.ismonitor():
        print("Cannot change channel. First you need to switch your iface to monitor mode.")
        return False
    else:
        iface.setchannel(n)
        return True # But it is still possible that it failed... Inside the scapy module.






def scan_ap(channels:list[int]=None, frequency:str=None, active:bool=False, iface=conf.iface):
    wifi_2_4_channels = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]
    wifi_5_channels = [36, 40, 44, 48, 149, 153, 157, 161]  # in KOREA
    ap_list = []
    current_channel = 0
    # Callback function that executes with each packet sniffed.
    #   [Input] a packet
    #   [Output] none
    def packet_handler_scan_ap(packet):
        # Passive Scan
        try:
            if packet.haslayer(Dot11Beacon):    # Beacon Frame
                netstats = packet[Dot11Beacon].network_stats()
                if ('channel' in netstats and netstats['channel'] == current_channel    # Discard frames from other channels
                        and packet.addr3 not in [ap['bssid'] for ap in ap_list]):
                    ap_list.append({
                        'ssid': netstats['ssid'],
                        'bssid': packet.addr3,
                        'channel': netstats['channel'],
                        'crypto': netstats['crypto']
                    })
                    print(ap_list[-1])
            '''
            if active:  # Active Scan
                if packet.type == 0 and (packet.subtype == 4 or packet.subtype == 5):    # Probe Request/Response Frame
                    ...
                    print('Sorry, active scanning is currently not supported.')
            '''
        except (KeyError, TypeError) as e:   # Probably a malformed packet
            ...


    if channels is None:
        if frequency is None:
            channels = wifi_2_4_channels + wifi_5_channels
        elif frequency.lower() == '2.4ghz':
            channels = wifi_2_4_channels
        elif frequency.lower() == '5ghz':
            channels = wifi_5_channels

    print('Start passive scan')
    iface_list = lookup_iface()
    iface = next((i for i in iface_list if i.description == '802.11n USB Wireless LAN Card'), None)
    iface.setmonitor(True)
    for n in channels:
        # Sequential channel switching - Stays for 1 second on each channel
        current_channel = n
        print('Current channel: %d' % n)
        switch_channel(n, iface)
        sniff(iface=iface, monitor=True, timeout=1, prn=packet_handler_scan_ap)
    iface.setmonitor(False)



if __name__ == '__main__':
    print(sys.argv)
    scan_ap()
