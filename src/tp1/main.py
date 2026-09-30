import sys

from tp1.utils.etapes import code_retour, generer_rapport, lancer_analyse, lancer_capture, lire_arguments


def main(argv: list[str] | None = None) -> int:
    """Lance les fonctions dans l'ordre"""
    args = lire_arguments(argv)
    capture = lancer_capture(args)
    lancer_analyse(capture)
    generer_rapport(capture, args.out)
    return code_retour(capture)


if __name__ == "__main__":
    sys.exit(main())
