'''A set of util functions and variables for the PIUS suite.'''

# vim:shiftwidth=2:tabstop=2:expandtab:textwidth=80:softtabstop=2:ai:
from __future__ import print_function

import re
from copy import copy
from libpius.constants import *
from optparse import Option, OptionValueError

DEBUG_ON = False
VALID_OPTIONS = [
    '--mail',
    '--signer',
    '--force-signer',
    '--use-agent',
    '--import',
    '--mail-host',
    '--mail-user',
    '--mail-port',
    '--mail-text',
    '--no-mail-tls',
    '--interactive',
    '--all-keys',
    '--gpg-agent',
    '--encrypt-outfiles',
    '--debug',
    '--no-sort-keyring',
    '--override-email',
    '--out-dir',
    '--no-pgp-mime',
    '--cache-passphrase',
    '--keyring',
    '--tmp-dir',
    '--policy-url',
    '--verbose',
]

def debug(line):
  '''Print a line, if debug is on, preceeded with "DEBUG: ".'''
  if DEBUG_ON:
      print('DEBUG:', line)


def logcmd(cmd):
  debug("Running: %s" % ' '.join(cmd))

def clean_files(flist):
  '''Delete a list of files.'''
  for cfile in flist:
    if os.path.exists(cfile):
      os.unlink(cfile)

def parse_dotfile(parser):
  tmp_file = PIUS_HOME + 'rc'
  sep = re.compile(r'(?:\s*=\s*|\s*:\s*\s+)')

  # Handle conversion of old rc file
  if os.path.isfile(PIUS_HOME):
    print('Converting ~/.pius to ~/.pius/piusrc')
    # temporarily rename ~/.pius to ~/.piusrc
    os.rename(PIUS_HOME, tmp_file)
    os.mkdir(PIUS_HOME, 0o755)
    os.rename(tmp_file, PIUS_RC)
  # Handle partial conversion
  elif os.path.isfile(tmp_file) and not os.path.islink(tmp_file):
    if not os.path.isdir(PIUS_HOME):
      os.mkdir(PIUS_HOME, 0o755)
    if not os.path.isfile(PIUS_RC):
      os.rename(tmp_file, PIUS_RC)
    else:
      print('WARNING: Both %s and %s exist... ignoring %s' %
            (PIUS_RC, tmp_file, tmp_file))

  # if we have a config file, parse it
  opts = []
  if os.path.isfile(PIUS_RC):
    fp = open(PIUS_RC, 'r')
    for line in fp:
      if line.startswith('#'):
        continue
      parts = sep.split(line.strip())
      if not parts[0].startswith('--'):
        parts[0] = '--%s' % parts[0]
      if parser.has_option(parts[0]):
        opts.extend(parts)
      elif not parts[0] in VALID_OPTIONS:
        print('WARNING: Invalid line "%s" in %s, ignoring.' %
              (line.strip(), PIUS_RC))
    fp.close()

  return opts

#
# Stupid fucking optparse will assume "-m -e" means "-e is the email address
# being passed to -m"... instead of "oh, -e is an option, -m is missing it's
# required argument. This is an ugly hack around that.
#

def check_not_another_opt(_, opt, value):
  '''Ensure argument to an option isn't another option.'''
  match = re.search(r'^\-', value)
  if match:
    raise OptionValueError('Option %s: Value %s looks like another option'
                           ' instead of the required argument' % (opt, value))
  return value

def check_email(_, opt, value):
  '''Ensure argument seems like an email address.'''
  match = re.match(r'.+@.+\..+', value)
  if not match:
    raise OptionValueError('Option %s: Value %s does not appear like a well'
                           ' formed email address' % (opt, value))
  return value

def check_keyid(_, opt, value):
  '''Ensure argument seems like a keyid.'''
  match = re.match(r'[0-9a-fA-Fx]', value)
  if not match:
    raise OptionValueError('Option %s: Value %s does not appear to be a KeyID'
                           % (opt, value))
  return value

class MyOption(Option):
  '''Our own option class.'''
  TYPES = Option.TYPES + ('not_another_opt', 'email', 'keyid')
  TYPE_CHECKER = copy(Option.TYPE_CHECKER)
  TYPE_CHECKER.update({
      'not_another_opt': check_not_another_opt,
      'email': check_email,
      'keyid': check_keyid,
  })

# END Stupid python optparse hack.

