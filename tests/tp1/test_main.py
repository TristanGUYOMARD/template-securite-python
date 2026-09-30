import json

from scapy.all import wrpcap

from src.tp1.main import main, parse_args
from tests.tp1 import pcap_factory as factory


def test_parse_args_defaults():
    # When
    args = parse_args([])

    # Then
    assert args.pcap is None
    assert args.out == "report.json"
    assert args.iface is None
    assert args.count == 0
    assert args.timeout == 30


def test_parse_args_with_options():
    # When
    args = parse_args(["--pcap", "a.pcap", "--out", "x/r.json", "--iface", "eth0", "-c", "5", "-t", "2"])

    # Then
    assert (args.pcap, args.out, args.iface, args.count, args.timeout) == ("a.pcap", "x/r.json", "eth0", 5, 2)


def test_given_pcap_when_main_then_reports_are_written(tmp_path):
    # Given
    pcap = tmp_path / "lab.pcap"
    wrpcap(str(pcap), factory.full_scenario())
    target = tmp_path / "out" / "report.json"

    # When
    code = main(["--pcap", str(pcap), "--out", str(target)])

    # Then
    assert code == 0
    data = json.loads(target.read_text(encoding="utf-8"))
    assert {a["type"] for a in data["attacks"]} == {"arp_spoofing", "port_scan", "sql_injection"}
    assert data["flag"] == factory.DEMO_FLAG
    assert (tmp_path / "out" / "report.pdf").exists()
    assert (tmp_path / "out" / "protocols.svg").exists()


def test_given_missing_pcap_when_main_then_error_code(tmp_path):
    # When
    code = main(["--pcap", str(tmp_path / "absent.pcap"), "--out", str(tmp_path / "report.json")])

    # Then
    assert code == 1
