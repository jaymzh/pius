'''The bulk of PIUS - al the magic to do individual UID signing.'''

# vim:shiftwidth=2:tabstop=2:expandtab:textwidth=80:softtabstop=2:ai:

from libpius.util import debug, clean_files, logcmd
from libpius.constants import *
from libpius.exceptions import *
import getpass
import os
import re
import subprocess
import sys


class PiusSigner(object):
  '''Main class for signing UIDs.'''

  TMP_KEYRING_FILE = 'pius_keyring.gpg'

  GPG_PROMPT = '[GNUPG:] GET_LINE keyedit.prompt'
  GPG_ACK = '[GNUPG:] GOT_IT'
  GPG_ALREADY_SIGNED = '[GNUPG:] ALREADY_SIGNED'
  GPG_CONFIRM = '[GNUPG:] GET_BOOL sign_uid.okay'
  GPG_SAVE = '[GNUPG:] GET_BOOL keyedit.save.okay'
  GPG_ENC_BEG = '[GNUPG:] BEGIN_ENCRYPTION'
  GPG_ENC_END = '[GNUPG:] END_ENCRYPTION'
  GPG_ENC_INV = '[GNUPG:] INV_RECP'
  GPG_KEY_EXP = '[GNUPG:] KEYEXPIRED'
  GPG_SIG_EXP = '[GNUPG:] SIGEXPIRED'
  GPG_USERID = '[GNUPG:] USERID_HINT'
  GPG_NEED_PASS = '[GNUPG:] NEED_PASSPHRASE'
  GPG_GOOD_PASS = '[GNUPG:] GOOD_PASSPHRASE'
  GPG_SIG_BEG = '[GNUPG:] BEGIN_SIGNING'
  GPG_SIG_CREATED = '[GNUPG:] SIG_CREATED'

  def __init__(self, signer, force_signer, mode, keyring, gpg_path, tmpdir,
               outdir, encrypt_outfiles, mail, mailer, verbose, sort_keyring,
               policy_url, mail_host):
    self.signer = signer
    if not force_signer:
      # If force_signer is not specified let gpg guess by using the main keyid
      self.force_signer = self.signer
    else:
      # If force_signer is specified make sure that gpg uses this keyid by
      # putting '!' at the end
      self.force_signer = force_signer + '!'
    self.mode = mode
    self.keyring = keyring
    self.sort_keyring = sort_keyring
    self.gpg = gpg_path
    self.tmpdir = tmpdir
    self.outdir = outdir
    self.encrypt_outfiles = encrypt_outfiles
    self.mail = mail
    self.mailer = mailer
    self.verbose = verbose
    self.passphrase = ''
    self.tmp_keyring = '%s/%s' % (self.tmpdir, PiusSigner.TMP_KEYRING_FILE)
    self.policy_url = policy_url
    self.mail_host = mail_host
    self.null = open(os.path.devnull, 'w')
    self.gpg_base_opts = [
          '--keyid-format', 'long',
          '--no-auto-check-trustdb',
    ]
    self.gpg_quiet_opts = [
          '-q',
          '--no-tty',
          '--batch',
    ]
    self.gpg_fd_opts = [
          '--command-fd', '0',
          '--status-fd', '1',
    ]
    self.gpg2 = self._is_gpg2()

    if not self.gpg2:
        self.gpg_fd_opts += ['--passphrase-fd', '0',]

    if self.mode == MODE_INTERACTIVE:
      try:
        global pexpect
        import pexpect
        global quote
        from pipes import quote
      except ImportError:
        parser.error('You chose interactive mode but do not have the pexpect'
                     ' module installed.')

  def _is_gpg2(self):
    cmd = [self.gpg, '--version']
    logcmd(cmd)
    gpg = subprocess.Popen(
        cmd,
        stdin=self.null,
        stdout=subprocess.PIPE,
        stderr=self.null,
    )

    v = None
    for line in gpg.stdout:
      # On Linux this looks like:
      #   gpg (GnuPG) 2.1.8
      # On Mac this looks like:
      #   gpg (GnuPG/MacGPG2) 2.0.28
      m = re.match(r'^gpg \(GnuPG.*\) ([0-9\.]+)$', line)
      if m:
        v = m.group(1)

    if not v:
      print "ERROR: Could not determine gpg version\n"
      sys.exit(1)

    return v.startswith('2.')

  def is_gpg2(self):
    return self.gpg2

  def _outfile_path(self, ofile):
    '''Internal function to take a filename and put it in self.outdir.'''
    return '%s/%s' % (self.outdir, ofile)

  def _tmpfile_path(self, tfile):
    '''Internal function to take a filename and put it in self.tmpdir.'''
    return '%s/%s' % (self.tmpdir, tfile)

  def cleanup(self):
    '''Cleanup all our temp files.'''
    clean_files([self.tmp_keyring, ('%s~' % self.tmp_keyring)])

  def get_all_keyids(self):
    '''Given a keyring, get all the KeyIDs from it.'''
    debug('extracting all keyids from keyring')
    cmd = [self.gpg] + self.gpg_base_opts + [
        '--no-default-keyring',
        '--keyring', self.keyring,
        '--no-options',
        '--with-colons',
        '--keyid-format', 'long',
        '--fingerprint',
        '--fixed-list-mode',
    ]
    logcmd(cmd)
    gpg = subprocess.Popen(
        cmd,
        stdin=self.null,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT
    )
    # We use 'pub' instead of 'fpr' to support old crufty keys too...
    pub_re = re.compile('^pub:')
    uid_re = re.compile('^uid:')
    key_tuples = []
    name = keyid = None
    for line in gpg.stdout:
      if pub_re.match(line):
        lineparts = line.split(':')
        keyid = lineparts[4]
      elif keyid and uid_re.match(line):
        lineparts = line.split(':')
        name = lineparts[9]
        debug('Got id %s for %s' % (keyid, name))
        key_tuples.append((name, keyid))
        name = keyid = None

    # sort the list
    if self.sort_keyring:
      keyids = [i[1] for i in sorted(key_tuples)]
    else:
      keyids = [i[1] for i in key_tuples]
    return keyids

  def _print_cert_levels(self):
    print CERT_LEVEL_INFO

  def check_fingerprint(self, key):
    '''Prompt the user to see if they have verified this fingerprint.'''
    cmd = [self.gpg] + self.gpg_base_opts + self.gpg_quiet_opts + [
        '--no-default-keyring',
        '--keyring', self.keyring,
        '--fingerprint', key,
    ]
    logcmd(cmd)
    gpg = subprocess.Popen(cmd,
                           stdin=self.null,
                           stdout=subprocess.PIPE,
                           stderr=self.null,
                           close_fds=True)
    output = gpg.stdout.read()
    output = output.strip()
    retval = gpg.wait()
    if retval != 0:
      print 'WARNING: Keyid %s not valid, skipping.' % key
      return False

    print output

    while True:
      ans = raw_input("\nHave you verified this user/key, and if so, what level"
                      " do you want to sign at?\n  0-3, Show again, Next, Help,"
                      " or Quit? [0|1|2|3|s|n|h|q] (default: n) ")
      print

      if ans == 'y':
        print ('"Yes" is no longer a valid answer, please specify a level to'
               ' sign at.')
      elif ans in ('n', 'N', ''):
        return False
      elif ans in ('s', 'S'):
        print output
      elif ans in ('0', '1', '2', '3'):
        return ans
      elif ans in ('?', 'h', 'H'):
        self._print_cert_levels()
      elif ans in ('q', 'Q'):
        print 'Dying at user request'
        sys.exit(1)

  def get_passphrase(self):
    '''Prompt the user for their passphrase.'''
    self.passphrase = getpass.getpass('Please enter your PGP passphrase: ')

  def verify_passphrase(self):
    '''Verify a passpharse gotten from get_passpharse().'''
    magic_string = 'test1234'
    filename = self._tmpfile_path('pius_tmp')
    filename_enc = self._tmpfile_path('pius_tmp.gpg')
    filename_dec = self._tmpfile_path('pius_tmp2')
    clean_files([filename, filename_enc, filename_dec])
    tfile = open(filename, 'w')
    tfile.write(magic_string)
    tfile.close()
    cmd = [self.gpg] + self.gpg_base_opts + self.gpg_quiet_opts + [
        '--no-armor',
        '--always-trust',
        '-r', self.signer,
        '-e', filename,
    ]
    logcmd(cmd)
    subprocess.call(cmd, stdout=self.null, stderr=self.null, close_fds=True)
    cmd = [self.gpg] + self.gpg_base_opts + self.gpg_quiet_opts + \
      self.gpg_fd_opts + [
          '--output', filename_dec,
          '-d', filename_enc,
      ]
    logcmd(cmd)
    gpg = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                           stdout=subprocess.PIPE,
                           stderr=self.null,
                           close_fds=True)

    debug('Sending passphrase')
    gpg.stdin.write('%s\n' % self.passphrase)

    line = gpg.stdout.read()
    debug('wait()ing on gpg')
    retval = gpg.wait()
    if retval != 0:
      debug('gpg decrypt return code %s' % retval)
      clean_files([filename, filename_enc, filename_dec])
      return False

    if not os.path.exists(filename_dec):
      debug('Resulting file %s not found' % filename_dec)
      clean_files([filename, filename_enc, filename_dec])
      return False
    tfile = open(filename_dec, 'r')
    line = tfile.readline()
    tfile.close()
    clean_files([filename, filename_enc, filename_dec])
    if line == magic_string:
      return True
    debug('File does not contain magic string')
    return False

  def get_uids(self, key):
    '''Get all UIDs on a given key.'''
    cmd = [self.gpg] + self.gpg_base_opts +  self.gpg_quiet_opts + \
      self.gpg_fd_opts + [
          '--no-default-keyring',
          '--keyring', self.keyring,
          '--no-options',
          '--with-colons',
          '--edit-key', key,
      ]
    logcmd(cmd)
    gpg = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                           stdout=subprocess.PIPE,
                           stderr=self.null,
                           close_fds=True)

    gpg.stdin.write('\n')
    uids = []
    unique_files = []
    while True:
      line = gpg.stdout.readline().strip()

      # skip the things we don't care about...
      if not line:
        debug('breaking, EOF')
        break
      if line == PiusSigner.GPG_PROMPT:
        debug('got to command prompt')
        break

      # Parse the line...
      debug('Got a line %s' % line)
      fields = line.split(':')

      if fields[0] != 'uid':
        continue

      status = fields[1]
      uid = fields[9]
      index = int(fields[13].split(',')[0])

      debug('Got UID %s with status %s' % (uid, status))

      # If we can we capture an email address is saved for
      # emailing off signed keys (not yet implemented), and
      # also for the ID for that UID.
      #
      # If we can't, then we grab what we can and make it the
      # id and blank out the email.
      #
      # For the normal case (have email), we'll be storing each email twice
      # but that's OK since it means that email is *always* a valid email or
      # None and id is *always* a valid identifier
      match = re.search('.* <(.*)>', uid)
      if match:
        email = match.group(1)
        debug('got email %s' % email)
        filename = re.sub('@', '_at_', email)
        filename = '%s__%s' % (key, filename)
        uid = email
      else:
        # but if it doesn't have an email, do the right thing
        email = None
        debug('no email')
        uid = re.sub(' ', '_', uid)
        uid = re.sub('\'', '', uid)
        filename = '%s__%s' % (key, uid)
      # Append the UID we're signing with in case people sign with 2
      # keys in succession:
      filename = '%s__%s' % (filename, self.signer)

      if filename in unique_files:
        debug('Filename is a duplicate')
        count = 2
        while True:
          test = '%s_%s' % (filename, count)
          debug('Trying %s' % test)
          if test not in unique_files:
            debug('%s worked!' % test)
            filename = test
            break
          else:
            count += 1
      else:
        debug('%s isn\'t in %s' % (filename, repr(unique_files)))

      # NOTE: Make sure to append the file BEFORE adding the extension
      #       since that's what we test against above!
      unique_files.append(filename)
      filename += '.asc'
      uids.append({'email': email, 'file': self._outfile_path(filename),
                   'status': status, 'id': uid, 'index': index})

    debug('quitting')
    # sometimes it wants a save here. I don't know why. We can quit and check
    # for a save prompt, and then hit no, but we have to make sure it's still
    # running or we'll hang. It's just easier to issue a 'save' instead of a
    # quit
    gpg.stdin.write('save\n')
    debug('waiting')
    gpg.wait()

    return uids

  def clean_working_keyring(self):
    '''Delete our temporariy working keyring.'''
    if os.path.exists(self.tmp_keyring):
      os.unlink(self.tmp_keyring)
    # Some versions of gpg won't create the keyring automatically
    # thought most seem to... anyway, we touch the file just in case
    open(self.tmp_keyring, 'w').close()

  def encrypt_signed_uid(self, key, filename):
    '''Encrypt the file we exported the signed UID to.'''
    (base, ext) = os.path.splitext(os.path.basename(filename))
    enc_file = '%s_ENCRYPTED%s' % (base, ext)
    enc_path = self._outfile_path(enc_file)
    if os.path.exists(enc_path):
      os.unlink(enc_path)
    cmd = [self.gpg] + self.gpg_base_opts + self.gpg_quiet_opts + \
      self.gpg_fd_opts + [
          '--no-default-keyring',
          '--keyring', self.tmp_keyring,
          '--always-trust',
          '--armor',
          '-r', key,
          '--output', enc_path,
          '-e', filename,
      ]
    logcmd(cmd)
    gpg = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                           stdout=subprocess.PIPE,
                           stderr=self.null,
                           close_fds=True)

    # Must send a blank line...
    gpg.stdin.write('\n')
    while True:
      debug('Waiting for response')
      line = gpg.stdout.readline().strip()
      debug('Got %s' % line)
      if PiusSigner.GPG_ENC_BEG in line:
        debug('Got GPG_ENC_BEG')
        continue
      elif PiusSigner.GPG_ENC_END in line:
        debug('Got GPG_ENC_END')
        break
      elif PiusSigner.GPG_ENC_INV in line:
        debug('Got GPG_ENC_INV')
        raise EncryptionKeyError
      elif (PiusSigner.GPG_KEY_EXP in line or
            PiusSigner.GPG_SIG_EXP in line):
        # These just mean we passed a given key/sig that's expired, there
        # may be ones left that are good. We cannot report an error until
        # we get a ENC_INV.
        debug('Got GPG_KEY_EXP')
        continue
      else:
        raise EncryptionUnknownError(line)

    gpg.wait()
    return enc_file

  def _run_and_check_status(self, cmd):
    '''Helper function for running a gpg call that requires no input
    but that we want to make sure succeeded.'''
    logcmd(cmd)
    gpg = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                           stdout=self.null,
                           stderr=self.null,
                           close_fds=True)
    retval = gpg.wait()
    if retval != 0:
      # We don't catch this, but that's fine, if this errors, a stack
      # trace is what we want
      raise GpgUnknownError

  def _export_key(self, keyring, keys, path):
    '''Internal function used by other export_* functions.'''
    if os.path.exists(path):
      os.unlink(path)
    cmd = [self.gpg] + self.gpg_base_opts + self.gpg_quiet_opts + [
        '--no-default-keyring',
        '--keyring', keyring,
        '--armor',
        '--output', path,
        '--export',
    ] + keys
    self._run_and_check_status(cmd)

  def export_signed_uid(self, key, filename):
    '''Export the signed UID form working keyring.'''
    debug('exporting %s' % key)
    self._export_key(self.tmp_keyring, [key], filename)

  def export_clean_key(self, key):
    '''Export clean key from the users' KeyID.'''
    debug('exporting %s' % key)
    # We have to export our own public key as well
    keys_to_export = [key, self.signer]
    path = self._tmpfile_path('%s.asc' % key)
    self._export_key(self.keyring, keys_to_export, path)

  def clean_clean_key(self, key):
    '''Delete the "clean" unsigned key which we exported temporarily.'''
    path = self._tmpfile_path('%s.asc' % key)
    clean_files([path])

  def import_clean_key(self, key):
    '''Import the clean key we expoerted in export_clean_key() to our temp
    keyring.'''
    path = self._tmpfile_path('%s.asc' %  key)
    cmd = [self.gpg] + self.gpg_base_opts + self.gpg_quiet_opts + [
        '--no-default-keyring',
        '--keyring', self.tmp_keyring,
        '--import-options', 'import-minimal',
        '--import', path,
    ]
    self._run_and_check_status(cmd)

  def policy_opts(self):
    if self.policy_url:
      return ['--cert-policy-url', self.policy_url]
    else:
      return []

  #
  # NOTE:
  #    This is a sucky hack. I may just completely delete it one day. The only
  #    reason it's still here is because agent support is flaky and some people
  #    may not like us storing their passphrase in memory.
  #
  def sign_uid_expect(self, key, index, level):
    '''Sign a UID, using the expect stuff. Interactive mode.'''
    cmd = [self.gpg] + self.gpg_base_opts + [
        '--no-default-keyring',
        '--keyring', self.tmp_keyring,
        '--default-cert-level', level,
        '--no-ask-cert-level',
        '--no-use-agent',
        '--edit-key', key,
    ] + self.policy_opts()
    logcmd(cmd)
    gpg = pexpect.spawn(' '.join((quote(arg) for arg in cmd)))
    gpg.setecho(False)
    gpg.expect('gpg> ')
    debug('Selecting UID %s' % index)
    gpg.sendline(str(index))
    gpg.expect('gpg> ')
    debug('Running sign subcommand')
    gpg.sendline('sign')
    line = gpg.readline()
    if 'already signed' in line:
      print '  UID already signed'
      return False
    # else it's a blank line...

    gpg.expect(re.compile('Really sign.*'))
    debug('Confirming signing')
    gpg.sendline('y')
    # Tell the user how to get out of this, and then drop them into the gpg
    # shell.
    print '\n\nPassing you to gpg for passphrase.'
    print 'Hit ^] after succesfully typing in your passphrase'
    gpg.interact()
    # When we return, we have a Command> prompt that w can't
    # 'expect'... or at least if the user did it right
    print ''
    # Unselect this UID
    debug('unselecting uid')
    debug('Saving key')
    gpg.sendline('save')
    return True

  def gpg_wait_for_string(self, fd, string):
    '''Look for a specific string on the status-fd.'''
    line = ''
    while line not in (string,):
      debug('Waiting for line %s' % string)
      line = fd.readline().strip()
      debug('got line %s' % line)

  def sign_uid(self, key, index, level):
    '''Sign a single UID of a key.

    This can use either cached passpharse or gpg-agent.'''
    agent = []
    if self.mode == MODE_AGENT:
      agent = ['--use-agent']
    keyring = ['--no-default-keyring', '--keyring', self.tmp_keyring]
    # Note that if passphrase-fd is different from command-fd, nothing works.
    cmd = [self.gpg] + self.gpg_base_opts + self.gpg_quiet_opts + \
      self.gpg_fd_opts + keyring + [
          '-u', self.force_signer,
      ] + agent + [
          '--default-cert-level', level,
          '--no-ask-cert-level',
          '--edit-key', key,
      ] + self.policy_opts()
    logcmd(cmd)
    gpg = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                           stdout=subprocess.PIPE,
                           stderr=self.null,
                           close_fds=True)

    if self.mode == MODE_AGENT:
      # For some reason when using agent an initial enter is needed
      if not self.gpg2:
          gpg.stdin.write('\n')
    else:
      # For some unidentified reason you must send the passphrase
      # first, not when it asks for it.
      debug('Sending passphrase')
      gpg.stdin.write('%s\n' % self.passphrase)


    debug('Waiting for prompt')
    self.gpg_wait_for_string(gpg.stdout, PiusSigner.GPG_PROMPT)
    debug('Selecting UID %d' % index)
    gpg.stdin.write('%s\n' % str(index))
    debug('Waiting for ack')
    self.gpg_wait_for_string(gpg.stdout, PiusSigner.GPG_ACK)

    debug('Running sign subcommand')
    self.gpg_wait_for_string(gpg.stdout, PiusSigner.GPG_PROMPT)
    debug('Sending sign command')
    gpg.stdin.write('sign\n')
    self.gpg_wait_for_string(gpg.stdout, PiusSigner.GPG_ACK)

    while True:
      debug('Waiting for response')
      line = gpg.stdout.readline()
      debug('Got %s' % line)
      if PiusSigner.GPG_ALREADY_SIGNED in line:
        print '  UID already signed'
        gpg.stdin.write('quit\n')
        return False
      elif (PiusSigner.GPG_KEY_EXP in line or
            PiusSigner.GPG_SIG_EXP in line):
        # The user has an expired signing or encryption key, keep going
        debug('Got GPG_KEY/SIG_EXP')
        continue
      elif PiusSigner.GPG_PROMPT in line:
        # Unfortunately PGP doesn't give us anything parsable in this case. It
        # just gives us another prompt. We give the most likely problem. Best we
        # can do.
        print ('  ERROR: GnuPG won\'t let us sign, this probably means it'
               ' can\'t find a secret key, which most likely means that the'
               ' keyring you are using doesn\'t have _your_ _public_ key on'
               ' it.')
        gpg.stdin.write('quit\n')
        raise NoSelfKeyError
      elif PiusSigner.GPG_CONFIRM in line:
        # This is what we want
        break
      else:
        print '  ERROR: GnuPG reported an unknown error'
        gpg.stdin.write('quit\n')
        # Don't raise an exception, it's not probably just this UID...
        return False

    debug('Confirming signing')
    gpg.stdin.write('Y\n')
    self.gpg_wait_for_string(gpg.stdout, PiusSigner.GPG_ACK)

    #
    # gpg-agent doesn't always work as well as we like. Of the problems:
    #  * It can't always pop up an X window reliably (pinentry problems)
    #  * It doesn't seem able to figure out the best pinetry program
    #    to use in many situations
    #  * Sometimes it silently fails in odd ways
    #
    # So this chunk of code will follow gpg through as many tries as gpg-agent
    # is willing to give and then inform the user of an error and raise an
    # exception.
    #
    # Since we're here, we also handle the highly unlikely case where the
    # verified cached passphrase doesn't work.
    #
    while True:
      line = gpg.stdout.readline()
      debug('Got %s' % line)
      # gpg1 + gpgagent1 reported BAD_PASSPHRASE for both the agent the wrong
      # passphrase, and for canceling the prompt.
      #
      # gpg2.0 + gpgagent2.0 seems to do MISSING_PASSPHRASE and BAD_PASSPHRASE
      # for the respective answers
      #
      # gpg2.1 + gpgagent2.1 seems to just do ERROR
      if 'ERROR' in line:
        print '  ERROR: Agent reported an error.'
        raise AgentError
      if 'MISSING_PASSPHRASE' in line:
        print '  ERROR: Agent didn\'t provide passphrase to PGP.'
        raise AgentError
      if 'BAD_PASSPHRASE' in line:
        if self.mode == MODE_AGENT:
          line = gpg.stdout.readline()
          debug('Got %s' % line)
          if 'USERID_HINT' in line:
            continue
          print '  ERROR: Agent reported the passphrase was incorrect.'
          raise AgentError
        else:
          print '  ERROR: GPG didn\'t accept the passphrase.'
          raise PassphraseError
      if 'GOOD_PASSPHRASE' in line:
        break
      if PiusSigner.GPG_PROMPT in line:
        if self.gpg2:
          break;
        print '  ERROR: GPG didn\'t sign.'
        raise GpgUnknownError(line)

    debug('Saving key')
    if not self.gpg2:
      self.gpg_wait_for_string(gpg.stdout, PiusSigner.GPG_PROMPT)
    gpg.stdin.write('save\n')

    gpg.wait()
    return True

  def print_filenames(self, uids):
    '''Print the filenames we created for the user.'''
    print '  Signed UNencrypted keys: '
    for uid in uids:
      if uid['status'] != 'r' and uid['result']:
        print '    %(id)s: %(file)s' % uid
    if self.encrypt_outfiles:
      print '  Signed encrypted keys: '
      for uid in uids:
        if uid['status'] != 'r' and uid['result']:
          print '    %(id)s: %(enc_file)s' % uids

  def sign_all_uids(self, key, level):
    '''The main function that signs all the UIDs on a given key.'''
    signed_any_uids = False
    uids = self.get_uids(key)
    print '  There %s %s UID%s on this key to sign' % (
        ['is', 'are'][len(uids) != 1], len(uids), "s"[len(uids) == 1:]
    )

    # From the user key ring make a clean copy
    self.export_clean_key(key)
    for uid in uids:
      if uid['status'] == 'r':
        print '  Skipping revoked uid %s' % uid['index']
        continue
      elif uid['status'] == 'e':
        print '  Skipping expired uid %s' % uid['index']
        continue
      sys.stdout.write('  UID %s (%s): ' % (uid['index'], uid['id']))

      # Make sure we have a clean keyring, and then import the key we care
      # about
      self.clean_working_keyring()
      self.import_clean_key(key)

      # Sign the key...
      if self.mode in (MODE_CACHE_PASSPHRASE, MODE_AGENT):
        try:
          res = self.sign_uid(key, uid['index'], level)
        except AgentError:
          print '\ngpg-agent problems, bailing out!'
          sys.exit(1)
        except PassphraseError:
          print ('\nThe passphrase that worked a moment ago now doesn\'t work.'
                 ' I\'m bailing out!')
          sys.exit(1)
        except NoSelfKeyError:
          print '\nWe don\'t have our own key, according to GnuPG.'
          # No need to say anything else
          sys.exit(1)
      else:
        res = self.sign_uid_expect(key, uid['index'], level)
      if not res:
        uid['result'] = False
        continue
      sys.stdout.write('signed')
      uid['result'] = True
      signed_any_uids = True

      # Export the signed key...
      self.export_signed_uid(key, uid['file'])

      # If requested, encrypt the signed key...
      if self.encrypt_outfiles:
        try:
          uid['enc_file'] = self._outfile_path(
              self.encrypt_signed_uid(key, uid['file'])
          )
          sys.stdout.write(', encrypted')
        except EncryptionKeyError:
          print ('\nEncryption failed due to invalid key error. User may not'
                 ' have an encryption subkey or it may be expired.')
          uid['enc_file'] = None
          # If we can't encrypt, we don't want to mail - even if we're using
          # PGP/Mime the encryption for that will also fail. So we move on to
          # the next key
          continue

      # If requested, send keys out. Note this doesn't depend on
      # encrypt_outfiles, because if we use PGP/Mime, the default, the email
      # itself is encrypted
      if self.mail:
        try:
          if uid['email'] == None:
            print '  WARNING: No email for %s, cannot send key.' % uid['id']
            continue
          # this is a ugly. The mailer needs to be able to be able to call
          # encrypt_and_sign_file() to be able to generate the PGP/MIME file,
          # so we pass outselves, it can call it...
          self.mailer.send_sig_mail(self.signer, key, uid, self)
          sys.stdout.write(', mailed')
        except MailSendError, msg:
          print ('\nThere was a problem talking to the mail server (%s): %s'
                 % (self.mail_host, msg))

      # add a newline to all the sys.stdout.write()s
      print ''

      # remove the signed file, if it exists (it might not, if it's
      # expired, the user chose not to sign it, etc.)
      # But don't do this if the ONLY action we're performing is creating those
      # files - then the desired result is these files.
      if self.encrypt_outfiles or self.mail:
        if os.path.exists(uid['file']):
          os.unlink(uid['file'])

    if self.verbose:
      self.print_filenames(uids)

    # Remove the clean keyfile we temporarily created
    self.clean_clean_key(key)
    return signed_any_uids

  def import_unsigned_keys(self):
    '''Import all the unsigned keys from keyring to main keyring.'''
    print 'Importing keyring...'
    cmd = [self.gpg] + self.gpg_base_opts + self.gpg_quiet_opts + [
        '--import', self.keyring,
    ]
    self._run_and_check_status(cmd)

  def encrypt_and_sign_file(self, infile, outfile, keyid):
    '''Encrypt and sign a file.

    Used for PGP/Mime email generation.'''
    agent = []
    if self.mode == MODE_AGENT:
      agent = ['--use-agent']
    cmd = [self.gpg] + self.gpg_base_opts +  self.gpg_quiet_opts + \
      self.gpg_fd_opts + agent + [
          '--no-default-keyring',
          '--keyring', self.tmp_keyring,
          '--no-options',
          '--always-trust',
          '-u', self.force_signer,
          '-aes',
          '-r', keyid,
          '-r', self.signer,
          '--output', outfile,
          infile,
      ]
    logcmd(cmd)
    gpg = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                           stdout=subprocess.PIPE,
                           stderr=self.null,
                           close_fds=True)

    if self.mode == MODE_AGENT:
      # For some reason when using agent an initial enter is needed
      gpg.stdin.write('\n')
    else:
      # For some unidentified reason you must send the passphrase
      # first, not when it asks for it.
      debug('Sending passphrase')
      gpg.stdin.write('%s\n' % self.passphrase)

    while True:
      debug('Waiting for response')
      line = gpg.stdout.readline().strip()
      debug('Got %s' % line)
      if PiusSigner.GPG_ENC_BEG in line:
        debug('Got GPG_ENC_BEG')
        continue
      elif PiusSigner.GPG_ENC_END in line:
        debug('Got GPG_ENC_END')
        break
      elif PiusSigner.GPG_ENC_INV in line:
        debug('Got GPG_ENC_INV')
        raise EncryptionKeyError
      elif (PiusSigner.GPG_KEY_EXP in line or
            PiusSigner.GPG_SIG_EXP in line):
        # These just mean we passed a given key/sig that's expired, there
        # may be ones left that are good. We cannot report an error until
        # we get a ENC_INV.
        debug('Got GPG_KEY/SIG_EXP')
        continue
      elif (PiusSigner.GPG_USERID in line or
            PiusSigner.GPG_NEED_PASS in line or
            PiusSigner.GPG_GOOD_PASS in line or
            PiusSigner.GPG_SIG_BEG in line or
            PiusSigner.GPG_SIG_CREATED in line):
        debug('Got skippable stuff')
        continue
      else:
        raise EncryptionUnknownError(line)

    retval = gpg.wait()
    if retval != 0:
      raise EncryptionUnknownError("Return code was %s" % retval)

# END class PiusSigner
