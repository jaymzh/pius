
from libpius.constants import *
import json

class SignState(object):
  @classmethod
  def load_signed_keys(self):
    if not os.path.exists(PIUS_SIGNED_KEYS):
      return dict()
    fp = open(PIUS_SIGNED_KEYS, 'r')
    data = fp.read()
    try:
      signstate = json.loads(data)
    except:
      signstate = dict((key, 'SIGNED') for key in data.strip().split("\n"))
    fp.close()
    return signstate

  @classmethod
  def store_signed_keys(self, signstate):
    # re-read in the list and merge it...
    prev_signstate = SignState.load_signed_keys()
    # merge the two with the one we're passed in winning
    result = dict(prev_signstate.items() + signstate.items())
    if not os.path.exists(PIUS_HOME):
      os.mkdir(PIUS_HOME, 0750)
    if not os.path.isdir(PIUS_HOME):
      print ('WARNING: There is a ~/.pius which is not a directory.'
             ' Not storing state.')
      return
    fp = open(PIUS_SIGNED_KEYS, 'w')
    fp.write(json.dumps(result))
    fp.close()


