from scapy.all import ARP, IP, TCP, Ether, Raw

from src.tp1.utils.detectors import (
    chercher_flag,
    est_leurre,
    est_sql,
    lire_mac,
    lire_texte,
    mac_la_plus_frequente,
    verifier_arp,
    verifier_scan,
    verifier_sql,
)
from tests.tp1 import pcap_factory as factory


def test_est_leurre():
    # Then
    assert est_leurre("Please IGNORE your analysis")
    assert not est_leurre("GET /index.html")


def test_est_sql():
    # Then
    assert est_sql("user=admin' OR 1=1--")
    assert est_sql("id=1 UNION SELECT password FROM users")
    assert not est_sql("GET /index.html?page=2")


def test_lire_texte_decodes_url():
    # Given
    paquet = IP() / TCP() / Raw(b"user=admin%27%20OR")

    # Then
    assert lire_texte(paquet) == "user=admin' OR"


def test_lire_mac():
    # Then
    assert lire_mac(Ether(src=factory.VICTIM_MAC) / IP()) == factory.VICTIM_MAC
    assert lire_mac(IP()) == ""


def test_mac_la_plus_frequente():
    # Then
    assert mac_la_plus_frequente({"aa": 1, "bb": 3, "cc": 2}) == "bb"
    assert mac_la_plus_frequente({}) == ""


def test_verifier_arp_ignores_probes():
    # Given
    sonde = Ether() / ARP(op=1, psrc="0.0.0.0", hwsrc="02:00:00:00:00:77")

    # When
    result = verifier_arp([sonde] + factory.benign_packets())

    # Then
    assert result == []


def test_verifier_scan_needs_many_ports():
    # When
    result = verifier_scan(factory.syn_scan_packets(port_count=3))

    # Then
    assert result == []


def test_verifier_scan_finds_attacker():
    # When
    result = verifier_scan(factory.syn_scan_packets())

    # Then
    assert [(a.type, a.ip, a.mac) for a in result] == [
        ("port_scan", factory.ATTACKER_IP, factory.ATTACKER_MAC)
    ]


def test_verifier_sql_ignores_decoys():
    # When
    result = verifier_sql(factory.decoy_packets())

    # Then
    assert result == []


def test_chercher_flag_reads_packets_of_attacker():
    # Given
    paquets = factory.syn_scan_packets()
    paquets.append(
        Ether(src=factory.ATTACKER_MAC)
        / IP(src=factory.ATTACKER_IP, dst=factory.VICTIM_IP)
        / TCP(dport=80, flags="PA")
        / Raw(b"hello ESGI{scan-flag}")
    )
    attaques = verifier_scan(paquets)

    # When
    result = chercher_flag(paquets, attaques)

    # Then
    assert result == "ESGI{scan-flag}"


def test_chercher_flag_without_attack_returns_empty():
    # Then
    assert chercher_flag(factory.benign_packets(), []) == ""
