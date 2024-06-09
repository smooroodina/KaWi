import re

import pytest
import os
import sys
import logging

# Logging 설정
logging.basicConfig(
    filename=os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'log', 'sniff.log'),
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s]%(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# scapy 패키지 경로 추가
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'scapy'))
from scapy.all import *  # noqa: E402
from scapy.consts import LINUX, WINDOWS

# KaWi.sniff 모듈 경로 추가
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
from KaWi.sniff import *

@pytest.fixture
def setup_inputs():
    iface_list = lookup_iface()
    if LINUX:
        input1 = 'wlan0'
        input2 = None
    elif WINDOWS:
        input1 = 'Wi-Fi'
        input2 = 'Wi-Fi 2'
    return iface_list, input1, input2

@pytest.fixture
def setup_ifaces(setup_inputs):
    iface_list, input1, input2 = setup_inputs
    iface_managed = from_name_to_iface(input1, iface_list)
    iface_monitor = from_name_to_iface(input2, iface_list)
    for iface in iface_list:
        iface_other = iface
        if iface != iface_managed and iface != iface_monitor:
            break
    return iface_managed, iface_monitor, iface_other

@pytest.fixture
def setup_networks(setup_ifaces):
    iface_managed, iface_monitor, _ = setup_ifaces
    network_list = scan_AP(iface=iface_monitor)
    network_connected = next((n for n in network_list if n.bssid == get_connected_wifi_bssid(iface_managed)), None)
    for network in network_list:
        network_other = network
        if network != connected_network:
            break

        # Should be removed
        network_connected.gateway = '192.168.0.1'
        network_connected.subnet = 24

    return network_connected, network_other


def test_lookup_iface():
    iface_list = lookup_iface()
    assert len(iface_list) > 0, '인터페이스 목록 탐색에 실패했습니다.'
    if LINUX:
        assert any(iface.name == 'wlan0' for iface in iface_list), '{} 인터페이스가 감지되지 않습니다.'.format('wlan0')
    elif WINDOWS:
        input1, input2 = 'Wi-Fi', 'Wi-Fi 2'
        assert any(iface.name == input1 for iface in iface_list), '{} 인터페이스가 감지되지 않습니다.'.format(input1)
        assert any(iface.name == input2 for iface in iface_list), '{} 인터페이스가 감지되지 않습니다.'.format(input2)

def test_from_name_to_iface(setup_inputs):
    iface_list, input1, _ = setup_inputs
    from_right_name = from_name_to_iface(input1, iface_list)
    assert isinstance(from_right_name, NetworkInterface), 'NetworkInterface 객체를 반환해야 합니다.'
    from_wrong_name = from_name_to_iface("wrongIfaceName404", iface_list)
    assert from_wrong_name is None, '존재하지 않는 이름에 대해서는 None을 반환해야 합니다.'
    from_none = from_name_to_iface(None, iface_list)
    assert from_none is None, '인터페이스 이름이 None이면 None을 반환해야 합니다.'

def test_set_two_ifaces_to_use(setup_inputs, setup_ifaces):
    iface_list, input1, input2 = setup_inputs
    iface_managed, iface_monitor, _ = setup_ifaces
    good_two_iface = set_two_ifaces_to_use(iface_managed, iface_monitor, None)
    assert good_two_iface, '인터페이스 객체로 등록에 문제가 있습니다.'
    good_two_iface_num = set_two_ifaces_to_use(str(1), str(len(iface_list) - 1), iface_list)
    assert good_two_iface_num, '인터페이스 번호로 등록에 문제가 있습니다.'
    good_two_iface_name = set_two_ifaces_to_use(input1, input2, iface_list)
    assert good_two_iface_name, '인터페이스 이름으로 등록에 문제가 있습니다.'

def test_get_connected_wifi_bssid(setup_ifaces):
    def is_valid_bssid(text):
        pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
        return re.match(pattern, text) is not None
    iface_managed, _, _ = setup_ifaces
    connected_network_bssid = get_connected_wifi_bssid(iface_managed)
    assert is_valid_bssid(connected_network_bssid) or connected_network is None, '현재 연결된 네트워크 정보를 정상적으로 불러오지 못했습니다.'


def test_get_mode(setup_ifaces):
    iface_managed, iface_monitor, iface_other = setup_ifaces
    get_managed = get_mode(iface_managed)
    assert get_managed == 'managed', 'managed 인터페이스의 모드를 정상적으로 인식하지 못했습니다.'
    get_monitor = get_mode(iface_monitor)
    assert get_monitor == 'monitor', 'monitor 인터페이스의 모드를 정상적으로 인식하지 못했습니다.'
    get_other = get_mode(iface_other)
    assert get_other is None, '무선 네트워크 인터페이스가 아닌 경우, 모드는 None을 반환해야 합니다.'

def test_set_mode(setup_ifaces):
    _, iface_monitor, _ = setup_ifaces
    set_managed = set_mode('managed', iface_monitor)
    assert set_managed, '인터페이스의 모드를 managed로 변환 중 오류가 발생했습니다.'
    assert get_mode(iface_monitor) == 'managed', '인터페이스의 모드가 managed로 변경되지 않았습니다.'

    set_monitor = set_mode('monitor', iface_monitor)
    assert set_monitor, '인터페이스의 모드를 monitor로 변환 중 오류가 발생했습니다.'
    assert get_mode(iface_monitor) == 'monitor', '인터페이스의 모드가 monitor로 변경되지 않았습니다.'

# def test_get_channel(setup_ifaces):

# def test_set_channel(setup_ifaces):

def test_scan_AP(setup_ifaces):
    _, iface_monitor, _ = setup_ifaces
    network_list_specified_channels = scan_AP(channels=[1, 2, 3, 4, 5, 6], iface=iface_monitor)
    assert len(network_list_specified_channels) > 0, '선택된 채널에서 네트워크 탐색에 실패했습니다.'
    network_list_2_4_frequency = scan_AP(frequency='2.4ghz', iface=iface_monitor)
    assert len(network_list_2_4_frequency) > 0, '2.4ghz 대역에서 네트워크 탐색에 실패했습니다.'
    network_list_5_frequency = scan_AP(frequency='5ghz', iface=iface_monitor)
    assert len(network_list_5_frequency) > 0, '5ghz 대역에서 네트워크 탐색에 실패했습니다.'


def test_scan_host(setup_ifaces, setup_networks):
    iface_managed, iface_monitor, _ = setup_ifaces
    network_connected, network_other = setup_networks
    host_list_in_connected_network = scan_host(network=None, iface_man=iface_managed, iface_mon=iface_monitor)
    assert len(host_list_in_connected_network) > 0, '현재 연결된 네트워크에서 Host 정보 목록을 수집하지 못했습니다.'
    # host_list_in_specified_network = scan_host(network=???, iface_man=iface_managed, iface_mon=iface_monitor)
    # assert len(host_list_in_specified_network) > 0, '특정 네트워크에 연결해서 Host 목록을 수집하지 못했습니다.'
    host_list_in_wrong_network = scan_host(network=network_other, iface_man=iface_managed, iface_mon=iface_monitor)
    assert host_list_in_wrong_network is None, '연결 불가능한 네트워크를 지정한 경우 None을 반환해야 합니다.'

def test_disconnect_client(setup_ifaces, setup_networks):
    _, iface_monitor, _ = setup_ifaces
    network_connected, network_wrong = setup_networks
    # client_MAC should be modified to a different target device MAC address for each testing environment.
    disconnect_specified_client = disconnect_client(network=network_connected, client_MAC='04:29:2e:79:4a:12', iface=iface_monitor)
    assert disconnect_specified_client, '지정된 client의 네트워크 연결이 해제되었는지 확인할 수 없습니다.'
    disconnect_broadcast = disconnect_client(network=network_connected, broadcast=True, iface=iface_monitor)
    assert disconnect_broadcast, '모든 client의 네트워크 연결이 해제되었는지 확인할 수 없습니다.'
    disconnect_wrong_client = disconnect_client(network=network_connected, client_MAC='00:00:00:00:00:00', iface=iface_monitor)
    assert not disconnect_wrong_client, '존재하지 않는 client를 대상으로 공격을 수행해서는 안 됩니다.'
    disconnect_wrong_network = disconnect_client(network=network_wrong, client_MAC='04:29:2e:79:4a:12', iface=iface_monitor)
    assert not disconnect_wrong_network, '존재하지 않는 network에 대해 공격을 수행해서는 안 됩니다.'

    