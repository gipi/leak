import logging

import math

import re
import sys

class UnexpectedPattern(Exception):
    pass

class Parser(object):
    '''Parser class that simply returns the data of interest from a leaking service

    Probably you want to use the RegexParser if your case is a simple static parameter
    matching, otherwise you have to subclass this with a more complex data retrieval case
    (like an XML parser).

    If the internal state of the parser need to be updated based on leaker decision,
    you have to implement the update method (and call it obviously).
    '''
    def __init__(self):
        super(Parser, self).__init__()

        self.logger = logging.getLogger(self.__class__.__name__)

    def get_leak(self, data):
        return data

    def update(self, *args, **kwargs):
        pass


class RegexParser(Parser):
    def __init__(self, pattern, regex_flags=None):
        super(RegexParser, self).__init__()

        self.pattern = pattern
        self.regex_flags = regex_flags or re.DOTALL|re.M

        self.regex = re.compile(self.pattern, self.regex_flags)

    def get_leak(self, data):
        leak = None
        try:
            leak = self.regex.match(data)
        except Exception as e:
            self.logger.exception(data)
            raise UnexpectedPattern('the string \'%s\' doesn\'t match the regex \'%s\'' % (
                data,
                self.regex,
            ))

        # TODO: maybe returns Status, data
        return leak.groupdict()



class LeakerEOS(Exception):
    '''Indicates that the stream doesn't have more data of interest'''
    pass

class BaseLeaker(object):
    '''
    This is the base class to use in order to create you own leaker.

    Roughly speaking the leaker launch via some channel sequentially
    some requests and extract the leaking data in order to reconstruct
    a certain global state of the underlying system to be exploited.

    Each request is called a **session**.

    The request content is manipulated using a Parser that extracts
    the essential data.

    TODO: how to make all of this multi-threading?
    '''
    def __init__(self, parser=None, **kwargs):
        if not parser:
            raise AttributeError('you must pass a valid parser instance')

        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.setLevel(logging.DEBUG)

        stream = logging.StreamHandler()
        formatter = logging.Formatter('%(levelname)s - %(filename)s:%(lineno)d - %(message)s')

        stream.setFormatter(formatter)

        self.logger.addHandler(stream)

        self.parser = parser

        # this two below are for session data
        self._data = None # this will contain the original data before parsing
        self._leak = None # this will contain the data extracted

        # this is a global state
        self._state = {} # this will contain the data structure to be reconstructed from the leaks

    def input(self, args, **kwargs):
        '''Here is where you call your channel and return some data to elaborate upon'''
        raise NotImplementedError('you have to implement input()')

    def get_next_input_parameters(self):
        raise NotImplementedError('you have to implemement get_next_input_parameter()')

    def update(self):
        """Update internal state after a leak using the dictionary returned from the parser."""
        raise NotImplementedError('you have to implement update()')

    def has_finished(self):
        raise NotImplementedError('you have to implement has_finished()')

    @property
    def state(self):
        '''
        Access the internal reconstructed data
        '''
        return self._state

    def extract(self):
        input_args, input_kwargs = self.get_next_input_parameters()
        self.logger.debug('args=%s kwargs=%s' % (input_args, input_kwargs))
        self._data = self.input(*input_args, **input_kwargs)
        self._leak = self.parser.get_leak(self._data)

        self.logger.debug('%s\n\n ->\n\n%s' % (self._data, self._leak))

    def on_session_start(self):
        pass

    def on_session_end(self):
        pass

    def on_end(self):
        pass

    def __call__(self):
        while not self.has_finished():
            # TODO: factorize inner code as an iterator
            try:
                self.on_session_start()

                self.extract() # here we obtain the first representation from the parser
                self.update() # here we elaborate the text to create some representation

                self.on_session_end()
            except LeakerEOS as e:
                break
            except KeyboardInterrupt:
                break

        self.on_end()

        return self.state


class StaticInputParametersMixin(object):
    def get_next_input_parameters(self):
        return (), {}


class HasFinishedMixin(object):
    def has_finished(self):
        return False


class BaseDicotomia(object):
    '''
    Base class to iteractively guess with boolean questions a given value.

    You have to subclass the __repr__() method to customize the data structure
    that fits your need.
    '''
    def __init__(self, N=None, alphabet=None):
        super(BaseDicotomia, self).__init__()

        if not N and not alphabet:
            raise ValueError('you must indicate one of \'N\' or \'alphabet\' parameters')

        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.setLevel(logging.DEBUG)

        self.alphabet = alphabet

        if alphabet: # deduce the number of bits needed for this alphabet
            N = int(math.ceil(math.log(len(alphabet), 2)))

        self.N = N # this is the number of bits needed to describe the result given the alphabet
        self.M = N - 1 # this is the decreasing index of the bit to be guessed

        self.value = 0
        self.range = [0, 2**N]

    def __repr__(self):
        if self.alphabet:
            return self.alphabet[self.range[0]:self.range[1]]
        else:
            return self.value

    def initialize(self):
        return str(self)

    def next_value(self, guess):
        #if self.M == 0:
        #    raise StopIteration()

        if self.has_finished():
            raise ValueError('this bisection was over')

        self.logger.debug('range before %s' % self.range)

        if guess:
            self.value += 2**self.M
            self.range[0] += 2**self.M
        else:
            self.range[1] = self.value + 2**self.M

        self.logger.debug('range after  %s' % self.range)

        self.M -= 1

        return self.__repr__()

    def has_finished(self):
        return self.range[0] == (self.range[1] - 1)
