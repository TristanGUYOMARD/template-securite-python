from src.tp1.utils.capture import Capture
from src.tp1.utils.etapes import code_retour, generer_rapport, lancer_analyse


def test_code_retour():
    # Given
    bonne = Capture(interface="eth0")
    mauvaise = Capture(interface="eth0")
    mauvaise.erreur = True

    # Then
    assert code_retour(bonne) == 0
    assert code_retour(mauvaise) == 1


def test_given_error_when_lancer_analyse_then_nothing_is_analysed():
    # Given
    capture = Capture(interface="eth0")
    capture.erreur = True

    # When
    lancer_analyse(capture)

    # Then
    assert capture.resume == ""


def test_given_error_when_generer_rapport_then_no_file_is_written(tmp_path):
    # Given
    capture = Capture(interface="eth0")
    capture.erreur = True

    # When
    generer_rapport(capture, str(tmp_path / "report.json"))

    # Then
    assert list(tmp_path.iterdir()) == []
