#!/usr/bin/env python

from distutils.core import setup
from libpius import constants
setup(
  name='pius',
  version=constants.VERSION,
  packages=['libpius'],
  requires=['six'],
  scripts=['pius', 'pius-keyring-mgr', 'pius-party-worksheet', 'pius-report'],
)
