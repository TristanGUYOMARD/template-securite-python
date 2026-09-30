from unittest.mock import patch

from src.tp1.utils.lib import choose_interface, default_interface, hello_world


def test_when_hello_world_then_return_hello_world():
    # Given
    string = "hello world"

    # When
    result = hello_world()

    # Then
    assert result == string


def test_given_env_var_when_choose_interface_then_return_it(monkeypatch):
    # Given
    monkeypatch.setenv("TP1_INTERFACE", "eth42")

    # When
    result = choose_interface()

    # Then
    assert result == "eth42"


def test_given_no_terminal_when_choose_interface_then_return_default(monkeypatch):
    # Given
    monkeypatch.delenv("TP1_INTERFACE", raising=False)

    # When
    with (
        patch("src.tp1.utils.lib.list_interfaces", return_value=["lo", "eth0"]),
        patch("src.tp1.utils.lib.default_interface", return_value="eth0"),
        patch("src.tp1.utils.lib.sys.stdin.isatty", return_value=False),
    ):
        result = choose_interface()

    # Then
    assert result == "eth0"


def test_given_interactive_terminal_when_choose_interface_then_use_user_choice(
    monkeypatch,
):
    # Given
    monkeypatch.delenv("TP1_INTERFACE", raising=False)

    # When
    with (
        patch("src.tp1.utils.lib.list_interfaces", return_value=["lo", "eth0"]),
        patch("src.tp1.utils.lib.default_interface", return_value="eth0"),
        patch("src.tp1.utils.lib.sys.stdin.isatty", return_value=True),
        patch("builtins.input", return_value="0"),
    ):
        result = choose_interface()

    # Then
    assert result == "lo"


def test_default_interface_falls_back_to_first_interface():
    # When
    with patch("src.tp1.utils.lib.conf") as conf:
        conf.iface = None
        result = default_interface(["eth0", "eth1"])

    # Then
    assert result == "eth0"
