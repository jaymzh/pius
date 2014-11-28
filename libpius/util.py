'''A set of util functions and variables for the PIUS suite.'''

import os

DEBUG_ON = False

def debug(line):
  '''Print a line, if debug is on, preceeded with "DEBUG: ".'''
  if DEBUG_ON:
    print 'DEBUG:', line

def clean_files(flist):
  '''Delete a list of files.'''
  for cfile in flist:
    if os.path.exists(cfile):
      os.unlink(cfile)
