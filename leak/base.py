import re
import sys

class UnexpectedPattern(Exception):
    pass

class Parser(object):
    def get_leak(self, data):
        return data


class RegexParser(Parser):
    '''Parser class that simply returns the data of interest from a leaking
    service'''
    def __init__(self, pattern, regex_flags=None):
        self.pattern = pattern
        self.regex_flags = regex_flags or re.DOTALL|re.M

        self.regex = re.compile(self.pattern, self.regex_flags)

    def get_leak(self, data):
        leak = None
        try:
            leak = self.regex.match(data)
        except Exception as e:
            print >> sys.stderr, " [!]", data
            raise e

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

        self.parser = parser

        # this two below are for session data
        self._data = None # this will contain the original data before parsing
        self._leak = None # this will contain the data extracted

        # this is a global state
        self._state = None # this will contain the data structure to be reconstructed from the leaks

    def input(self, args, **kwargs):
        '''Here is where you call your channel and return some data to elaborate upon'''
        raise NotImplementedError('you have to implement input()')

    def get_next_input_parameters(self):
        raise NotImplementedError('you have to implemement get_next_input_parameter()')

    def update(self):
        """Update internal state after a leak using the dictionary returned from the parser."""
        raise NotImplementedError('you have to implement update()')

    @property
    def state(self):
        '''
        Access the internal reconstructed data
        '''
        return self._state

    def extract(self):
        self._data = self.input(self.get_next_input_parameters())
        self._leak = self.parser.get_leak(self._data)

    def has_finished(self):
        return NotImplementedError('you have to implement has_finished()')

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
