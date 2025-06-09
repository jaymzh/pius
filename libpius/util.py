"""A set of util functions and variables for the PIUS suite."""

# vim:shiftwidth=4:tabstop=4:expandtab:textwidth=80:softtabstop=4:ai:

import os
import re
from copy import copy
from optparse import Option, OptionValueError

from libpius.constants import HOME


class PiusUtil:
    DEBUG_ON = False
    EXPAND_USER_OPTIONS = [
        "--gpg-path",
        "--keyring",
        "--mail-text",
        "--out-dir",
        "--tmp-dir",
    ]
    FALLBACK_PIUSRC_PATH = os.path.join(HOME, ".pius")

    def debug(line):
        """Print a line, if debug is on, preceded with "DEBUG: "."""
        if PiusUtil.DEBUG_ON:
            print("DEBUG:", line)

    def logcmd(cmd):
        outcmd = " ".join(cmd) if type(cmd) == list else cmd
        PiusUtil.debug("Running: %s" % outcmd)

    def clean_files(flist):
        """Delete a list of files."""
        for cfile in flist:
            if os.path.exists(cfile):
                os.unlink(cfile)

    def statedir():
        # if the base XDG_DATA_HOME exists, (not our directory within, but the
        # top level directory, usually ~/.local/share), then we'll use that,
        # otherwise fall back to our own pathing.
        xdg_data = os.environ.get(
            "XDG_DATA_HOME", os.path.join(HOME, ".local", "share")
        )
        if os.path.exists(xdg_data):
            state_dir = os.path.join(xdg_data, "pius")
        else:
            state_dir = os.path.join(HOME, ".pius")
        PiusUtil.debug("Data dir: %s" % state_dir)
        return state_dir

    def previous_statedirs():
        return [os.path.join(HOME, ".pius")]

    def configdir():
        # if the base XDG_CONFIG_HOME exists, (not our directory within, but the
        # top level directory, usually ~/.config), then we'll use that,
        # otherwise fall back to our own pathing.
        xdg_home = os.environ.get(
            "XDG_CONFIG_HOME", os.path.join(HOME, ".config")
        )
        if os.path.exists(xdg_home):
            return os.path.join(xdg_home, "pius")
        return os.path.join(HOME, ".pius")

    def dotfile_path():
        # if the base XDG_CONFIG_HOME exists, (not our directory within, but the
        # top level directory, usually ~/.config), then we'll use that,
        # otherwise fall back to our own pathing.
        return os.path.join(PiusUtil.configdir(), "piusrc")

    def previous_dotfile_paths():
        return [
            os.path.join(PiusUtil.FALLBACK_PIUSRC_PATH, "piusrc"),
            os.path.join(HOME, ".pius"),
        ]

    def migrate_file(old, new):
        print("WARNING: Migrating %s to %s" % (old, new))
        d = os.path.dirname(new)
        if not os.path.isdir(d):
            os.mkdir(d, 0o750)
        os.rename(old, new)
        os.symlink(new, old)

    def handle_path_migration(new_path, old_paths):
        PiusUtil.debug("Migration to from %s -> %s" % (old_paths, new_path))
        for path in old_paths:
            # if we don't have XDG than one our desired RC *is* one of the old
            # paths, so don't try to convert between the same file and itself
            if path == new_path:
                continue
            # If this old path doesn't exist at all, cool
            if not os.path.exists(path):
                continue
            # If the new file doesn't exist and the old file does, convert it.
            if not os.path.exists(new_path) and os.path.exists(path):
                PiusUtil.migrate_file(path, new_path)
            # If the new file exists and the old file is a symlink, we're good
            elif os.path.exists(new_path) and os.path.islink(path):
                continue
            # If they're both a file, warn
            elif (
                os.path.exists(new_path)
                and os.path.exists(path)
                and os.path.islink(path)
            ):
                print(
                    "WARNING: Both %s and %s exist... ignoring %s"
                    % (new_path, path, path)
                )
                continue

    def parse_dotfile(parser):
        # People need a way to debug the parsing of the dotfile, which is before
        # command-line parsing is done. So, of PIUS_DEBUG=1 in the env, we go
        # ahead and turn debug on early.
        if int(os.environ.get("PIUS_DEBUG", 0)) > 0:
            PiusUtil.DEBUG_ON = True

        sep = re.compile(r"(?:\s*=\s*|\s*:\s*\s+)")

        piusrc = PiusUtil.dotfile_path()
        PiusUtil.handle_path_migration(
            piusrc, PiusUtil.previous_dotfile_paths()
        )

        # if we have a config file, parse it
        opts = []
        if os.path.isfile(piusrc):
            fp = open(piusrc, "r")
            for line in fp:
                if line.startswith("#"):
                    continue
                parts = sep.split(line.strip())
                if not parts[0].startswith("--"):
                    parts[0] = "--%s" % parts[0]
                if parts[0] in PiusUtil.EXPAND_USER_OPTIONS and len(parts) > 1:
                    parts[1] = os.path.expanduser(parts[1])
                if parser.has_option(parts[0]):
                    opts.extend(parts)
                else:
                    PiusUtil.debug(
                        "Line '%s' in %s is unknown, but that may be because "
                        "that option doesn't exist for this mode, so ignoring."
                        % (line.strip(), piusrc)
                    )
            fp.close()

        return opts


#
# Stupid fucking optparse will assume "-m -e" means "-e is the email address
# being passed to -m"... instead of "oh, -e is an option, -m is missing its
# required argument. This is an ugly hack around that.
#
def check_not_another_opt(_, opt, value):
    """Ensure argument to an option isn't another option."""
    match = re.search(r"^\-", value)
    if match:
        raise OptionValueError(
            "Option %s: Value %s looks like another option"
            " instead of the required argument" % (opt, value)
        )
    return value


def check_email(_, opt, value):
    """Ensure argument seems like an email address."""
    match = re.match(r".+@.+\..+", value)
    if not match:
        raise OptionValueError(
            "Option %s: Value %s does not appear like a well"
            " formed email address" % (opt, value)
        )
    return value


def check_display_name(_, opt, value):
    """Ensure argument is a valid email display name."""
    match = re.search(r'[()<>[\]:;@\\,."]', value)
    if match:
        raise OptionValueError(
            "Option %s: Value %s contains one or more illegal"
            " characters" % (opt, value)
        )
    return value


def check_keyid(_, opt, value):
    """Ensure argument seems like a keyid."""
    match = re.match(r"[0-9a-fA-Fx]", value)
    if not match:
        raise OptionValueError(
            "Option %s: Value %s does not appear to be a KeyID" % (opt, value)
        )
    return value


class MyOption(Option):
    """Our own option class."""

    TYPES = Option.TYPES + ("not_another_opt", "email", "display_name", "keyid")
    TYPE_CHECKER = copy(Option.TYPE_CHECKER)
    TYPE_CHECKER.update(
        {
            "not_another_opt": check_not_another_opt,
            "email": check_email,
            "display_name": check_display_name,
            "keyid": check_keyid,
        }
    )


# END Stupid python optparse hack.
