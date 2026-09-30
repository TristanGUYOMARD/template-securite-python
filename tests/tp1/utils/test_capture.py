from unittest.mock import patch

from scapy.all import IP, Ether, IPv6, wrpcap

from src.tp1.utils.capture import Capture, trouver_protocole
from tests.tp1 import pcap_factory as factory


def capture_with(packets: list) -> Capture:
    capture = Capture(interface="test0")
    capture.paquets = packets
    return capture


def test_capture_init_with_interface():
    # When
    capture = Capture(interface="eth0")

    # Then
    assert capture.interface == "eth0"
    assert capture.resume == ""
    assert capture.paquets == []


def test_capture_init_without_interface_asks_the_user():
    # When
    with patch("src.tp1.utils.capture.choisir_interface", return_value="eth9"):
        capture = Capture()

    # Then
    assert capture.interface == "eth9"


def test_given_interface_when_capturer_then_sniff_is_used():
    # Given
    capture = Capture(interface="eth0")

    # When
    with patch("src.tp1.utils.capture.sniff", return_value=factory.benign_packets()) as sniff:
        capture.capturer(nombre=5, delai=3)

    # Then
    sniff.assert_called_once_with(iface="eth0", count=5, timeout=3, store=True)
    assert len(capture.paquets) == len(factory.benign_packets())


def test_given_pcap_when_capturer_then_packets_are_read(tmp_path):
    # Given
    pcap = tmp_path / "lab.pcap"
    wrpcap(str(pcap), factory.full_scenario())
    capture = Capture(chemin_pcap=str(pcap))

    # When
    capture.capturer()

    # Then
    assert capture.interface == ""
    assert len(capture.paquets) == len(factory.full_scenario())


def test_trouver_protocole():
    # Given
    arp, _, dns, syn, *_, ping = factory.benign_packets()

    # Then
    assert trouver_protocole(arp) == "ARP"
    assert trouver_protocole(dns) == "DNS"
    assert trouver_protocole(syn) == "TCP"
    assert trouver_protocole(ping) == "ICMP"


def test_compter_protocoles_counts_packets():
    # Given
    capture = capture_with(factory.benign_packets())

    # When
    result = capture.compter_protocoles()

    # Then
    assert result == {"TCP": 4, "ARP": 2, "DNS": 1, "ICMP": 1}


def test_given_empty_capture_when_analyser_then_everything_is_fine():
    # Given
    capture = capture_with([])

    # When
    capture.analyser()

    # Then
    assert capture.attaques == []
    assert capture.compter_protocoles() == {}
    assert "Tout va bien" in capture.resume


def test_given_benign_traffic_when_analyser_then_everything_is_fine():
    # Given
    capture = capture_with(factory.benign_packets())

    # When
    capture.analyser()

    # Then
    assert capture.attaques == []
    assert "Tout va bien" in capture.resume
    assert capture.donnees_json()["attacks"] == []


def test_given_arp_spoofing_when_analyser_then_attacker_mac_is_found():
    # Given
    capture = capture_with(factory.benign_packets() + factory.arp_spoofing_packets())

    # When
    capture.analyser()

    # Then
    assert [(a.type, a.mac) for a in capture.attaques] == [("arp_spoofing", factory.ATTACKER_MAC)]
    assert not capture.est_legitime("ARP")
    assert capture.est_legitime("DNS")


def test_given_forged_arp_request_and_second_gateway_when_analyser_then_every_extra_mac_is_blamed():
    # Given
    packets = factory.benign_packets() + factory.second_gateway_packets() + factory.forged_arp_requests()
    capture = capture_with(packets)

    # When
    capture.analyser()

    # Then
    assert {a.mac for a in capture.attaques} == {"02:00:00:00:00:02", factory.ATTACKER_MAC}


def test_given_gateway_claimed_by_two_macs_when_analyser_then_second_mac_is_blamed():
    # Given
    capture = capture_with(factory.benign_packets() + factory.second_gateway_packets())

    # When
    capture.analyser()

    # Then
    assert [a.mac for a in capture.attaques] == ["02:00:00:00:00:02"]


def test_given_syn_scan_when_analyser_then_attacker_is_found():
    # Given
    capture = capture_with(factory.benign_packets() + factory.syn_scan_packets())

    # When
    capture.analyser()

    # Then
    assert [(a.type, a.attaquant) for a in capture.attaques] == [("port_scan", factory.ATTACKER_IP)]


def test_given_sql_injection_when_analyser_then_attack_and_flag_are_reported():
    # Given
    capture = capture_with(factory.benign_packets() + factory.sql_injection_packets())

    # When
    capture.analyser()

    # Then
    assert [(a.type, a.mac, a.ip) for a in capture.attaques] == [
        ("sql_injection", factory.ATTACKER_MAC, factory.ATTACKER_IP)
    ]
    assert capture.flag == factory.DEMO_FLAG


def test_given_decoy_text_when_analyser_then_it_is_not_an_attack_and_flag_is_not_read():
    # Given
    capture = capture_with(factory.benign_packets() + factory.decoy_packets())

    # When
    capture.analyser()

    # Then
    assert capture.attaques == []
    assert capture.flag == ""


def test_given_full_scenario_when_analyser_then_report_dict_has_expected_format():
    # Given
    capture = capture_with(factory.full_scenario() + factory.decoy_packets())

    # When
    capture.analyser()
    result = capture.donnees_json()

    # Then
    assert {a["type"] for a in result["attacks"]} == {"arp_spoofing", "port_scan", "sql_injection"}
    assert {a["attacker"] for a in result["attacks"]} == {factory.ATTACKER_MAC, factory.ATTACKER_IP}
    assert all(set(a) == {"type", "attacker"} for a in result["attacks"])
    assert result["protocols"]["ARP"] == 8
    assert result["flag"] == factory.DEMO_FLAG


def test_given_protocol_filter_when_analyser_then_only_those_protocols_are_checked():
    # Given
    capture = capture_with(factory.full_scenario())

    # When
    capture.analyser("arp")

    # Then
    assert [a.type for a in capture.attaques] == ["arp_spoofing"]


def test_analyser_calls_its_steps():
    # Given
    capture = Capture(interface="eth0")

    # When
    with (
        patch.object(capture, "compter_protocoles") as mock_compter,
        patch.object(capture, "faire_resume") as mock_faire_resume,
    ):
        mock_faire_resume.return_value = "Test summary"
        capture.analyser()

    # Then
    mock_compter.assert_called_once()
    mock_faire_resume.assert_called_once()
    assert capture.resume == "Test summary"


def test_trouver_protocole_other_layers():
    # Then
    assert trouver_protocole(Ether() / IPv6()) == "IPv6"
    assert trouver_protocole(Ether() / IP()) == "IP"
    assert trouver_protocole(Ether()) == "Other"
