import logging
import string

import pytest
from leak.base import Parser, BaseDicotomia
from leak.leak import TextFileLeaker


logging.basicConfig()


def test_stdin_leaker():
    leaker = TextFileLeaker('/etc/passwd', parser=Parser())

    print leaker()

def test_dictomia():
    value_to_guess = 255

    guesser = BaseDicotomia(N=8)

    print guesser.initialize()

    guesses = [True, True, True, True, True, True, True, True]

    print [guesser.next_value(_) for _ in guesses]
    assert guesser.has_finished()

    print guesser.value

    guesses = [False, False, True, False, False, False]

    guesser = BaseDicotomia(alphabet=string.letters)

    print guesser.initialize()

    print [guesser.next_value(_) for _ in guesses]

    print guesser.has_finished()