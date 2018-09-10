'''A set of path functions and variables for the PIUS suite.'''

# vim:shiftwidth=2:tabstop=2:expandtab:textwidth=80:softtabstop=2:ai:
import os

def which(pgm):
  path=os.getenv('PATH')
  for p in path.split(os.path.pathsep):
    p=os.path.join(p,pgm)
    if os.path.exists(p) and os.access(p,os.X_OK):
        return p

def gpg_test():
    gpg2 = which("gpg2")
    if gpg2 != "":
        return gpg2
    else:
        return "/usr/bin/gpg2"

# END Stupid python optparse hack.
