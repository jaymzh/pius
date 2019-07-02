# vim:shiftwidth=2:tabstop=2:expandtab:textwidth=80:softtabstop=2:ai:
import json
import os
import shutil

from libpius.util import PiusUtil


class SignState:
  # States for our intention/state on other keys
  kSIGNED = 'SIGNED'
  kWILL_NOT_SIGN = 'WILL_NOT_SIGN'
  kNOT_SIGNED = 'NOT_SIGNED'

  # States for other's intention on our keys
  kIGNORE = 'IGNORE'
  kNO_IGNORE = 'NO_IGNORE'

  # Direction
  kOUTBOUND = 'OUTBOUND'
  kINBOUND = 'INBOUND'

  kSIGNED_KEYS_DB_NAME = 'signed_keys'

  # metadata for current format
  kFILE_METADATA = {'_meta': {'version': 3}}

  def __init__(self):
    self.signed_keys_db = os.path.join(PiusUtil.statedir(),
                                       self.kSIGNED_KEYS_DB_NAME)
    self.state = {}
    self._load()
    self.modified = False

  def _load(self):
    self.state = self.load_signed_keys()

  def _validate_value(self, direction, val):
    if direction == self.kOUTBOUND:
      assert(val in [
        self.kSIGNED, self.kWILL_NOT_SIGN, self.kNOT_SIGNED
      ])
    else:
      assert(val in [self.kIGNORE, self.kNO_IGNORE, None])

  def __iter__(self):
    return self.state.__iter__()

  def signed(self, key):
    return key in self.state and self.state[key][self.kOUTBOUND] == self.kSIGNED

  def will_not_sign(self, key):
    return key in self.state and self.state[key][self.kOUTBOUND] == \
        self.kWILL_NOT_SIGN

  def expect_sig(self, key):
    return not (key in self.state and
                self.state[key][self.kINBOUND] == self.kIGNORE)

  def update_outbound(self, key, val):
    return self.update(key, self.kOUTBOUND, val)

  def update_inbound(self, key, val):
    return self.update(key, self.kINBOUND, val)

  def update(self, key, direction, val):
    # we don't store NOT_SIGNED, it's meaningless.
    if direction == self.kOUTBOUND and val == self.kNOT_SIGNED:
      return
    self._validate_value(direction, val)
    if key not in self.state:
      self.state[key] = {
          self.kOUTBOUND: None,
          self.kINBOUND: None,
      }
    self.state[key][direction] = val
    self.modified = True

  def save(self):
    self.store_signed_keys(self.state)

  def convert_from_v2(self, signstate):
    newstate = {}
    for k, v in signstate.items():
      newstate[k] = {self.kOUTBOUND: v, self.kINBOUND: None}
    return newstate

  def convert_from_v1(self, data):
    """
    If it is not JSON, it's the original format of one signed key per line
    """
    return (dict((key, {self.kOUTBOUND: 'SIGNED', self.kINBOUND: None})
            for key in data.strip().split("\n")))

  def load_signed_keys(self):
    PiusUtil.handle_path_migration(
      self.signed_keys_db,
      [
        os.path.join(x, self.kSIGNED_KEYS_DB_NAME) for x in
        PiusUtil.previous_statedirs()
      ]
    )

    if not os.path.exists(self.signed_keys_db):
      return dict()
    with open(self.signed_keys_db, 'r') as fp:
      data = fp.read()
      # We have had multiple versions of the state file.
      #
      # v1 was just one key per line, each key was "signed"
      #
      # v2 was a hash taking the form:
      #   key: (SIGNED | WILL_NOTSIGN | NOT_SIGNED)
      #
      # v3 was the first one with a version identifier in it. It includes
      # a `meta` entry for the version and any other future metadata.
      # The data itself takes the format of:
      #   key: {
      #     'OUTBOUND': (SIGNED | WILL_NOTSIGN | NOT_SIGNED | None),
      #     'OUTBOUND': (None | Ignore),
      #   }
      try:
        signstate = json.loads(data)
        if '_meta' in signstate and signstate['_meta']['version'] == 3:
          PiusUtil.debug('Loading v3 PIUS statefile')
          del(signstate['_meta'])
        elif '_meta' not in signstate:
          PiusUtil.debug('Loading v2 PIUS statefile')
          signstate = self.convert_from_v2(signstate)
      except ValueError:
        PiusUtil.debug('Loading v1 PIUS statefile')
        signstate = self.convert_from_v1(data)
    return signstate

  def store_signed_keys(self, signstate):
    # re-read in the list and merge it...
    prev_signstate = self.load_signed_keys()
    # merge the two with the one we're passed in winning
    prev_signstate.update(signstate)
    prev_signstate.update(self.kFILE_METADATA)
    self.write_file(prev_signstate)

  def write_file(self, data):
    '''Separated out for easier unittesting'''
    if not os.path.exists(PiusUtil.statedir()):
      os.mkdir(PiusUtil.statedir(), 0o750)
    if not os.path.isdir(PiusUtil.statedir()):
      print('WARNING: There is a %s which is not a directory.'
            ' Not storing state.' % PiusUtil.statedir())
      return
    if os.path.exists(self.signed_keys_db):
      shutil.copy(self.signed_keys_db, self.signed_keys_db + '.save')
    with open(self.signed_keys_db, 'w') as fp:
      fp.write(json.dumps(data))
