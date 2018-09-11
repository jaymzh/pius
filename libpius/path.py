'''A set of path functions and variables for the PIUS suite.'''
from __future__ import print_function

import os
import sys
import stat
from os.path import abspath
import fnmatch

'''This is grabbed right from the python repo under lib/shutil.py'''

def which(cmd, mode=os.F_OK | os.X_OK, path=None):
    """Given a command, mode, and a PATH string, return the path which
    conforms to the given mode on the PATH, or None if there is no such
    file.
    `mode` defaults to os.F_OK | os.X_OK. `path` defaults to the result
    of os.environ.get("PATH"), or can be overridden with a custom search
    path.
    """
    # Check that a given file can be accessed with the correct mode.
    # Additionally check that `file` is not a directory, as on Windows
    # directories pass the os.access check.
    def _access_check(fn, mode):
        return (os.path.exists(fn) and os.access(fn, mode)
                and not os.path.isdir(fn))

    # If we're given a path with a directory part, look it up directly rather
    # than referring to PATH directories. This includes checking relative to the
    # current directory, e.g. ./script
    if os.path.dirname(cmd):
        if _access_check(cmd, mode):
            return cmd
        return None

    if path is None:
        path = os.environ.get("PATH", os.defpath)
    if not path:
        return None
    path = path.split(os.pathsep)

    if sys.platform == "win32":
        # The current directory takes precedence on Windows.
        if not os.curdir in path:
            path.insert(0, os.curdir)

        # PATHEXT is necessary to check on Windows.
        pathext = os.environ.get("PATHEXT", "").split(os.pathsep)
        # See if the given file matches any of the expected path extensions.
        # This will allow us to short circuit when given "python.exe".
        # If it does match, only test that one, otherwise we have to try
        # others.
        if any(cmd.lower().endswith(ext.lower()) for ext in pathext):
            files = [cmd]
        else:
            files = [cmd + ext for ext in pathext]
    else:
        # On other platforms you don't have things like PATHEXT to tell you
        # what file suffixes are executable, so just pass on cmd as-is.
        files = [cmd]

    seen = set()
    for dir in path:
        normdir = os.path.normcase(dir)
        if not normdir in seen:
            seen.add(normdir)
            for thefile in files:
                name = os.path.join(dir, thefile)
                if _access_check(name, mode):
                    return name
    return None

def gpg_test():
    gpg = which('gpg2')
    if gpg == "":
        print("GPG2 could not be found! Is it accessable to $PATH?")
        sys.exit(1)
    else:
        return gpg

def get_home():
    if sys.platform == "win32":
        return os.environ.get('APPDATA')
    else:
        return os.environ.get('HOME')

def get_gpghome(HOME):
    if sys.platform == "win32":
        return os.environ.get('GNUPGHOME', os.path.join(HOME, 'roaming\/gnupg'))
    else:
        return os.environ.get('GNUPGHOME', os.path.join(HOME, '.gnupg'))

def get_piushome(HOME):
    if sys.platform == "win32":
        return os.path.join(HOME, 'roaming\/pius')
    else:
        return os.path.join(HOME, '.pius')

def set_tmpdir(dir):
    if sys.platform == "win32":
        TMP = os.environ.get('TEMP')
        return os.path.join(TMP, dir)
    elif sys.platfrom == "darwin":
        TMP = '/private/tmp/'
        return os.path.join(TMP, dir)
    else:
        TMP = '/tmp/'
        return os.path.join(TMP, dir)

# END Stupid python optparse hack.
