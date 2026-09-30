from unittest.mock import patch

from src.tp1.utils.lib import choisir_interface, interface_par_defaut, lister_interfaces


def test_given_env_var_when_choisir_interface_then_return_it(monkeypatch):
    # Given
    monkeypatch.setenv("TP1_INTERFACE", "eth42")

    # When
    result = choisir_interface()

    # Then
    assert result == "eth42"


def test_given_no_terminal_when_choisir_interface_then_return_default(monkeypatch):
    # Given
    monkeypatch.delenv("TP1_INTERFACE", raising=False)

    # When
    with (
        patch("src.tp1.utils.lib.lister_interfaces", return_value=["lo", "eth0"]),
        patch("src.tp1.utils.lib.interface_par_defaut", return_value="eth0"),
        patch("src.tp1.utils.lib.sys.stdin.isatty", return_value=False),
    ):
        result = choisir_interface()

    # Then
    assert result == "eth0"


def test_given_interactive_terminal_when_choisir_interface_then_use_user_choice(
    monkeypatch,
):
    # Given
    monkeypatch.delenv("TP1_INTERFACE", raising=False)

    # When
    with (
        patch("src.tp1.utils.lib.lister_interfaces", return_value=["lo", "eth0"]),
        patch("src.tp1.utils.lib.interface_par_defaut", return_value="eth0"),
        patch("src.tp1.utils.lib.sys.stdin.isatty", return_value=True),
        patch("builtins.input", return_value="0"),
    ):
        result = choisir_interface()

    # Then
    assert result == "lo"


def test_interface_par_defaut_falls_back_to_first_interface():
    # When
    with patch("src.tp1.utils.lib.conf") as conf:
        conf.iface = None
        result = interface_par_defaut(["eth0", "eth1"])

    # Then
    assert result == "eth0"


def test_lister_interfaces_returns_names():
    # When
    with patch("src.tp1.utils.lib.get_if_list", return_value=["lo", "eth0"]):
        result = lister_interfaces()

    # Then
    assert result == ["lo", "eth0"]


def test_lister_interfaces_error_returns_empty_list():
    # When
    with patch("src.tp1.utils.lib.get_if_list", side_effect=OSError("boom")):
        result = lister_interfaces()

    # Then
    assert result == []


def test_interface_par_defaut_uses_scapy_interface():
    # When
    with patch("src.tp1.utils.lib.conf") as conf:
        conf.iface = "wlan0"
        result = interface_par_defaut(["eth0"])

    # Then
    assert result == "wlan0"


def test_interface_par_defaut_without_interfaces_returns_empty():
    # When
    with patch("src.tp1.utils.lib.conf") as conf:
        conf.iface = None
        result = interface_par_defaut([])

    # Then
    assert result == ""


def test_given_invalid_answer_when_choisir_interface_then_return_default(monkeypatch):
    # Given
    monkeypatch.delenv("TP1_INTERFACE", raising=False)

    # When
    with (
        patch("src.tp1.utils.lib.lister_interfaces", return_value=["lo", "eth0"]),
        patch("src.tp1.utils.lib.interface_par_defaut", return_value="eth0"),
        patch("src.tp1.utils.lib.sys.stdin.isatty", return_value=True),
        patch("builtins.input", return_value="abc"),
    ):
        result = choisir_interface()

    # Then
    assert result == "eth0"
