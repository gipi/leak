import logging
import string

import pytest
from leak.base import Parser, BaseDicotomia
from leak.leak import TextFileLeaker


logging.basicConfig()


def test_stdin_leaker():
    leaker = TextFileLeaker('/etc/passwd', parser=Parser())

    print leaker()

def test_dicotomia():
    guesser = BaseDicotomia(N=8)

    guesses = [True, True, True, True, True, True, True, True]

    assert guesser.guess == '128'

    print [guesser.submit_oracle(_) for _ in guesses]
    assert guesser.has_finished()

    print guesser.value

    guesses = [True, False, False, False, False, False]

    alphabet = 'abcde'

    guesser = BaseDicotomia(alphabet=alphabet)

    assert guesser.guess == 'ab'

    assert guesser.submit_oracle(True) == 'ab'
    assert guesser.guess == 'a'
    assert guesser.submit_oracle(False) == 'b'

    print guesser.has_finished()

    guesser_alphanumeric = BaseDicotomia(alphabet=string.letters+string.digits)
    print guesser_alphanumeric.guess
    print guesser_alphanumeric.submit_oracle(True)