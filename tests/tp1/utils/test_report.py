import json

from src.tp1.utils.capture import Capture
from src.tp1.utils.report import Report
from tests.tp1 import pcap_factory as factory


def analysed_capture() -> Capture:
    capture = Capture(interface="test0")
    capture.packets = factory.full_scenario()
    capture.analyse()
    return capture


def test_report_init():
    # Given
    capture = Capture(interface="eth0")

    # When
    report = Report(capture, "test.pdf", "Test summary")

    # Then
    assert report.capture == capture
    assert report.filename == "test.pdf"
    assert report.summary == "Test summary"
    assert report.array == []
    assert report.graph == []


def test_generate_array_flags_illegitimate_protocols():
    # Given
    report = Report(analysed_capture(), "test.pdf", "summary")

    # When
    report.generate("array")

    # Then
    status = {protocol: state for protocol, _, _, state in report.array}
    assert status["ARP"] == "ILLÉGITIME"
    assert status["TCP"] == "ILLÉGITIME"
    assert status["DNS"] == "Légitime"


def test_generate_graph_lists_protocol_counts():
    # Given
    report = Report(analysed_capture(), "test.pdf", "summary")

    # When
    report.generate("graph")

    # Then
    assert dict(report.graph)["ARP"] == 8


def test_generate_invalid_param_changes_nothing():
    # Given
    report = Report(analysed_capture(), "test.pdf", "summary")

    # When
    report.generate("invalid")

    # Then
    assert report.graph == []
    assert report.array == []


def test_concat_report_contains_all_parts():
    # Given
    report = Report(analysed_capture(), "test.pdf", "Test summary")
    report.title = "Test Title"
    report.generate("array")
    report.generate("graph")

    # When
    result = report.concat_report()

    # Then
    assert result.startswith("Test Title")
    assert "Test summary" in result
    assert "ARP" in result


def test_save_writes_a_pdf(tmp_path):
    # Given
    report = Report(analysed_capture(), "unused.pdf", "Synthèse de test")
    report.generate("graph")
    report.generate("array")
    target = tmp_path / "report.pdf"

    # When
    report.save(str(target))

    # Then
    assert target.read_bytes().startswith(b"%PDF")


def test_save_json_matches_correction_format(tmp_path):
    # Given
    report = Report(analysed_capture(), "unused.pdf", "summary")
    target = tmp_path / "report.json"

    # When
    report.save_json(str(target))

    # Then
    data = json.loads(target.read_text(encoding="utf-8"))
    assert set(data) == {"protocols", "attacks", "flag"}
    assert {"type": "arp_spoofing", "attacker": factory.ATTACKER_MAC} in data["attacks"]
    assert data["flag"] == factory.DEMO_FLAG


def test_save_svg_chart(tmp_path):
    # Given
    report = Report(analysed_capture(), "unused.pdf", "summary")
    report.generate("graph")
    target = tmp_path / "protocols.svg"

    # When
    report.save_svg_chart(str(target))

    # Then
    assert "<svg" in target.read_text(encoding="utf-8")
