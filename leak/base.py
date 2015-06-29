import re

class UnexpectedPattern(Exception):
    pass

class Parser(object):
    def get_leak(self, data):
        return data


class RegexParser(Parser):
    def __init__(self, pattern):
        self.pattern = pattern

    def get_leak(self, data):
        pattern = re.compile(self.pattern, re.DOTALL|re.M)

        leak = ""
        try:
            leak = pattern.findall(data)[0]
        except Exception as e:
            print >> sys.stderr, " [!]", data
            raise e

        return leak



class LeakerEOS(Exception):
    '''Indicates that the stream doesn't have more data of interest'''
    pass

class Leaker(object):
    def __init__(self, parser=None, **kwargs):
        if not parser:
            raise AttributeError('you must pass a valid parser instance')

        self.parser = parser

    def input(self):
        raise NotImplementedError('you have to implement input()')

    def get_next_input_parameter(self):
        pass

    def update(self, leak):
        """Update internal state after a leak"""
        return leak

    def output(self, leak_piece):
        """Decides howto emit the leak"""
        raise NotImplementedError('you must implement output()')

    def extract(self):
        return self.parser.get_leak(self.input())

    def has_finished(self):
        return False

    def on_exit(self):
        pass

    def __call__(self):
        while not self.has_finished():
            try:
                representation = self.extract() # here we obtain the first representation from the parser
                representation = self.update(representation) # here we elaborate the text to create some representation
                self.output(representation)
            except LeakerEOS as e:
                break
            #    print >> sys.stderr, "fatal:", e
            #    raise e

        self.on_exit()
