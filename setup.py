#!/usr/bin/env python3

from distutils.core import setup
from libpius import constants
setup(
  name='pius',
  version=constants.VERSION,
  packages=['libpius'],
  scripts=['pius', 'pius-keyring-mgr', 'pius-party-worksheet', 'pius-report'],
  data_files=[
    (
      'share/man/man1', [
        'doc/pius-keyring-mgr.1',
        'doc/pius.1',
        'doc/pius-report.1',
        'doc/pius-party-worksheet.1'
      ]
    )
  ]
)
