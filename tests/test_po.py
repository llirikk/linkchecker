# -*- coding: iso-8859-1 -*-
# Copyright (C) 2005 Joe Wreschnig, Bastian Kleineidam
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

import os
import glob
from tests import make_suite, StandardTest


pofiles = None
def set_pofiles ():
    global pofiles
    if pofiles is None:
        pofiles = []
        pofiles.extend(glob.glob("po/*.po"))
        pofiles.extend(glob.glob("doc/*.po"))


class TestPo (StandardTest):

    needed_resources = ['posix', 'msgfmt']

    def test_pos (self):
        set_pofiles()
        for f in pofiles:
            ret = os.system("msgfmt -c -o - %s > /dev/null" % f)
            self.assertEquals(ret, 0, msg="PO-file syntax error in %r" % f)


class TestGTranslator (StandardTest):

    def test_gtranslator (self):
        set_pofiles()
        for f in pofiles:
            fd = file(f)
            try:
                self.check_file(fd, f)
            finally:
                fd.close()

    def check_file (self, fd, f):
        for line in fd:
            if line.strip().startswith("#"):
                continue
            self.failIf("\xc2\xb7" in line,
                 "Broken GTranslator copy/paste in %r:\n%r" % (f, line))


def test_suite ():
    """
    Build and return a TestSuite.
    """
    prefix = __name__.split(".")[-1]
    return make_suite(prefix, globals())