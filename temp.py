# 기능별로 모듈을 구분해 개발하기 전에 이 파일에서 작성하여 잘 작동하는지 실행시켜 봅니다.
import os
import sys

sys.path.append(os.path.dirname(os.path.abspath(__file__)) + '\\scapy')
from scapy.all import *     # noqa: E402
from scapy.automaton import *



class AccessPointAutomaton(Automaton):

    def parse_args(self, interface='Wi-Fi 2', ssid='MyAP', **kwargs):
        self.interface = interface
        self.ssid = ssid
        Automaton.parse_args(self, **kwargs)

    @ATMT.state(initial=1)
    def START(self):
        print("Starting AP Automaton...")
        raise self.SENDING_BEACON()

    @ATMT.state()
    def SENDING_BEACON(self):
        print("Sending beacon frames...")
        self.send_beacon()
        raise self.WAITING()

    @ATMT.state()
    def WAITING(self):
        print("Waiting for packets...")

    @ATMT.receive_condition(WAITING)
    def packet_received(self, pkt):
        if pkt.haslayer(Dot11):
            if pkt.type == 0 and pkt.subtype == 4:  # Probe Request
                print(f"Probe request received from {pkt.addr2}")
                self.send_probe_response(pkt)
            elif pkt.type == 0 and pkt.subtype == 11:  # Authentication
                print(f"Authentication request received from {pkt.addr2}")
                self.send_auth_response(pkt)
            elif pkt.type == 0 and pkt.subtype == 0:  # Association Request
                print(f"Association request received from {pkt.addr2}")
                self.send_assoc_response(pkt)
            raise self.WAITING()

    def send_beacon(self):
        dot11 = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2='02:00:00:00:01:00',
                      addr3='02:00:00:00:01:00')
        beacon = Dot11Beacon(cap='ESS+privacy')
        essid = Dot11Elt(ID='SSID', info=self.ssid, len=len(self.ssid))
        frame = RadioTap() / dot11 / beacon / essid
        sendp(frame, iface=self.interface, inter=0.1, loop=1, verbose=False)

    def send_probe_response(self, pkt):
        dot11 = Dot11(type=0, subtype=5, addr1=pkt.addr2, addr2='02:00:00:00:01:00', addr3='02:00:00:00:01:00')
        probe_resp = Dot11ProbeResp(cap='ESS+privacy')
        essid = Dot11Elt(ID='SSID', info=self.ssid, len=len(self.ssid))
        frame = RadioTap() / dot11 / probe_resp / essid
        sendp(frame, iface=self.interface, verbose=False)

    def send_auth_response(self, pkt):
        dot11 = Dot11(type=0, subtype=11, addr1=pkt.addr2, addr2='02:00:00:00:01:00', addr3='02:00:00:00:01:00')
        auth = Dot11Auth(seqnum=2)
        frame = RadioTap() / dot11 / auth
        sendp(frame, iface=self.interface, verbose=False)

    def send_assoc_response(self, pkt):
        dot11 = Dot11(type=0, subtype=1, addr1=pkt.addr2, addr2='02:00:00:00:01:00', addr3='02:00:00:00:01:00')
        assoc_resp = Dot11AssoResp()
        frame = RadioTap() / dot11 / assoc_resp
        sendp(frame, iface=self.interface, verbose=False)

    @ATMT.state(final=1)
    def END(self):
        print("Stopping AP Automaton...")

    @ATMT.timeout(WAITING, 1)
    def timeout(self):
        raise self.SENDING_BEACON()

    @ATMT.action(timeout)
    def start_sniffing(self):
        self.sniff(iface=self.interface, prn=self.master.recv, store=False)


if __name__ == "__main__":
    automaton = AccessPointAutomaton()
    automaton.run()