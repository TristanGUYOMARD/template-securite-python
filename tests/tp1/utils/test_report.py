import json

from src.tp1.utils.capture import Capture
from src.tp1.utils.report import Report
from tests.tp1 import pcap_factory as factory


def capture_analysee() -> Capture:
    capture = Capture(interface="test0")
    capture.paquets = factory.full_scenario()
    capture.analyser()
    return capture


def test_report_init():
    # Given
    capture = Capture(interface="eth0")

    # When
    report = Report(capture, "Test summary")

    # Then
    assert report.capture == capture
    assert report.resume == "Test summary"
    assert report.tableau == []
    assert report.graphique == []


def test_preparer_tableau_flags_illegitimate_protocols():
    # Given
    report = Report(capture_analysee(), "summary")

    # When
    report.preparer_tableau()

    # Then
    status = {protocol: state for protocol, _, _, state in report.tableau}
    assert status["ARP"] == "ILLÉGITIME"
    assert status["TCP"] == "ILLÉGITIME"
    assert status["DNS"] == "Légitime"


def test_preparer_graphique_lists_protocol_counts():
    # Given
    report = Report(capture_analysee(), "summary")

    # When
    report.preparer_graphique()

    # Then
    assert dict(report.graphique)["ARP"] == 8


def test_save_writes_a_pdf(tmp_path):
    # Given
    report = Report(capture_analysee(), "Synthèse de test")
    report.preparer_graphique()
    report.preparer_tableau()
    target = tmp_path / "report.pdf"

    # When
    report.sauver_pdf(str(target))

    # Then
    assert target.read_bytes().startswith(b"%PDF")


def test_save_json_matches_correction_format(tmp_path):
    # Given
    report = Report(capture_analysee(), "summary")
    target = tmp_path / "report.json"

    # When
    report.sauver_json(str(target))

    # Then
    data = json.loads(target.read_text(encoding="utf-8"))
    assert set(data) == {"protocols", "attacks", "flag"}
    assert {"type": "arp_spoofing", "attacker": factory.ATTACKER_MAC} in data["attacks"]
    assert data["flag"] == factory.DEMO_FLAG


def test_save_svg_chart(tmp_path):
    # Given
    report = Report(capture_analysee(), "summary")
    report.preparer_graphique()
    target = tmp_path / "protocols.svg"

    # When
    report.sauver_svg(str(target))

    # Then
    assert "<svg" in target.read_text(encoding="utf-8")


def test_empty_capture_report(tmp_path):
    # Given
    capture = Capture(interface="test0")
    capture.analyser()
    report = Report(capture, capture.resume)
    report.preparer_graphique()
    report.preparer_tableau()
    target = tmp_path / "report.pdf"

    # When
    report.sauver_pdf(str(target))

    # Then
    assert report.tableau == []
    assert target.read_bytes().startswith(b"%PDF")
