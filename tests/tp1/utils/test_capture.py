from unittest.mock import patch

from scapy.all import wrpcap

from src.tp1.utils.capture import Capture, get_protocol
from tests.tp1 import pcap_factory as factory


def capture_with(packets: list) -> Capture:
    capture = Capture(interface="test0")
    capture.packets = packets
    return capture


def test_capture_init_with_interface():
    # When
    capture = Capture(interface="eth0")

    # Then
    assert capture.interface == "eth0"
    assert capture.summary == ""
    assert capture.packets == []


def test_capture_init_without_interface_asks_the_user():
    # When
    with patch("src.tp1.utils.capture.choose_interface", return_value="eth9"):
        capture = Capture()

    # Then
    assert capture.interface == "eth9"


def test_given_interface_when_capture_traffic_then_sniff_is_used():
    # Given
    capture = Capture(interface="eth0")

    # When
    with patch("src.tp1.utils.capture.sniff", return_value=factory.benign_packets()) as sniff:
        capture.capture_traffic(count=5, timeout=3)

    # Then
    sniff.assert_called_once_with(iface="eth0", count=5, timeout=3, store=True)
    assert len(capture.packets) == len(factory.benign_packets())


def test_given_pcap_when_capture_traffic_then_packets_are_read(tmp_path):
    # Given
    pcap = tmp_path / "lab.pcap"
    wrpcap(str(pcap), factory.full_scenario())
    capture = Capture(pcap_path=str(pcap))

    # When
    capture.capture_traffic()

    # Then
    assert capture.interface == ""
    assert len(capture.packets) == len(factory.full_scenario())


def test_get_protocol():
    # Given
    arp, _, dns, syn, *_, ping = factory.benign_packets()

    # Then
    assert get_protocol(arp) == "ARP"
    assert get_protocol(dns) == "DNS"
    assert get_protocol(syn) == "TCP"
    assert get_protocol(ping) == "ICMP"


def test_get_all_protocols_counts_packets():
    # Given
    capture = capture_with(factory.benign_packets())

    # When
    result = capture.get_all_protocols()

    # Then
    assert result == {"TCP": 4, "ARP": 2, "DNS": 1, "ICMP": 1}


def test_sort_network_protocols_groups_packets():
    # Given
    capture = capture_with(factory.benign_packets())

    # When
    result = capture.sort_network_protocols()

    # Then
    assert set(result) == {"TCP", "ARP", "DNS", "ICMP"}
    assert len(result["ARP"]) == 2


def test_given_empty_capture_when_analyse_then_everything_is_fine():
    # Given
    capture = capture_with([])

    # When
    capture.analyse()

    # Then
    assert capture.attacks == []
    assert capture.get_all_protocols() == {}
    assert "Tout va bien" in capture.get_summary()


def test_given_benign_traffic_when_analyse_then_everything_is_fine():
    # Given
    capture = capture_with(factory.benign_packets())

    # When
    capture.analyse()

    # Then
    assert capture.attacks == []
    assert "Tout va bien" in capture.get_summary()
    assert capture.to_report_dict()["attacks"] == []


def test_given_arp_spoofing_when_analyse_then_attacker_mac_is_found():
    # Given
    capture = capture_with(factory.benign_packets() + factory.arp_spoofing_packets())

    # When
    capture.analyse()

    # Then
    assert [(a.type, a.mac) for a in capture.attacks] == [("arp_spoofing", factory.ATTACKER_MAC)]
    assert not capture.is_protocol_legit("ARP")
    assert capture.is_protocol_legit("DNS")


def test_given_forged_arp_request_and_second_gateway_when_analyse_then_every_extra_mac_is_blamed():
    # Given
    packets = factory.benign_packets() + factory.second_gateway_packets() + factory.forged_arp_requests()
    capture = capture_with(packets)

    # When
    capture.analyse()

    # Then
    assert {a.mac for a in capture.attacks} == {"02:00:00:00:00:02", factory.ATTACKER_MAC}


def test_given_gateway_claimed_by_two_macs_when_analyse_then_second_mac_is_blamed():
    # Given
    capture = capture_with(factory.benign_packets() + factory.second_gateway_packets())

    # When
    capture.analyse()

    # Then
    assert [a.mac for a in capture.attacks] == ["02:00:00:00:00:02"]


def test_given_syn_scan_when_analyse_then_attacker_is_found():
    # Given
    capture = capture_with(factory.benign_packets() + factory.syn_scan_packets())

    # When
    capture.analyse()

    # Then
    assert [(a.type, a.attacker) for a in capture.attacks] == [("port_scan", factory.ATTACKER_IP)]


def test_given_sql_injection_when_analyse_then_attack_and_flag_are_reported():
    # Given
    capture = capture_with(factory.benign_packets() + factory.sql_injection_packets())

    # When
    capture.analyse()

    # Then
    assert [(a.type, a.mac, a.ip) for a in capture.attacks] == [
        ("sql_injection", factory.ATTACKER_MAC, factory.ATTACKER_IP)
    ]
    assert capture.flag == factory.DEMO_FLAG


def test_given_decoy_text_when_analyse_then_it_is_not_an_attack_and_flag_is_not_read():
    # Given
    capture = capture_with(factory.benign_packets() + factory.decoy_packets())

    # When
    capture.analyse()

    # Then
    assert capture.attacks == []
    assert capture.flag == ""


def test_given_full_scenario_when_analyse_then_report_dict_has_expected_format():
    # Given
    capture = capture_with(factory.full_scenario() + factory.decoy_packets())

    # When
    capture.analyse()
    result = capture.to_report_dict()

    # Then
    assert {a["type"] for a in result["attacks"]} == {"arp_spoofing", "port_scan", "sql_injection"}
    assert {a["attacker"] for a in result["attacks"]} == {factory.ATTACKER_MAC, factory.ATTACKER_IP}
    assert all(set(a) == {"type", "attacker"} for a in result["attacks"])
    assert result["protocols"]["ARP"] == 8
    assert result["flag"] == factory.DEMO_FLAG


def test_given_protocol_filter_when_analyse_then_only_those_protocols_are_checked():
    # Given
    capture = capture_with(factory.full_scenario())

    # When
    capture.analyse("arp")

    # Then
    assert [a.type for a in capture.attacks] == ["arp_spoofing"]


def test_analyse_calls_its_steps():
    # Given
    capture = Capture(interface="eth0")

    # When
    with (
        patch.object(capture, "get_all_protocols") as mock_get_protocols,
        patch.object(capture, "sort_network_protocols") as mock_sort,
        patch.object(capture, "_gen_summary") as mock_gen_summary,
    ):
        mock_gen_summary.return_value = "Test summary"
        capture.analyse()

    # Then
    mock_get_protocols.assert_called_once()
    mock_sort.assert_called_once()
    mock_gen_summary.assert_called_once()
    assert capture.summary == "Test summary"


def test_get_summary():
    # Given
    capture = Capture(interface="eth0")
    capture.summary = "Test summary"

    # When
    result = capture.get_summary()

    # Then
    assert result == "Test summary"
