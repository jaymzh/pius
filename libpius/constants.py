# vim:shiftwidth=4:tabstop=4:expandtab:textwidth=80:softtabstop=4:ai:

import os
import re

VERSION = "3.0.0"

HOME = os.environ.get("HOME")
GNUPGHOME = os.environ.get("GNUPGHOME", os.path.join(HOME, ".gnupg"))
DEFAULT_GPG_PATH = "/usr/bin/gpg"
DEFAULT_KEYRING = os.path.join(GNUPGHOME, "pubring.kbx")
DEFAULT_TMP_DIR = "/tmp/pius_tmp"
DEFAULT_OUT_DIR = "/tmp/pius_out"
DEFAULT_MAIL_HOST = "localhost"
DEFAULT_MAIL_PORT = 587

# used instead of base_opts by pius-report
# which is in fact using the default keyring
GPG_MIN_OPTS = [
    "--use-agent",
    "--keyid-format", "long",
    # not strictly speaking necessary, but no need to slow pius-report
    # down by checking the trustdb in the middle of things
    "--no-auto-check-trustdb",
]

GPG_BASE_OPTS = [
    "--use-agent",
    "--keyid-format", "long",
    "--no-default-keyring",
    # must be specified anytime no-default-keyring is specified
    "--no-auto-check-trustdb",
]
GPG_QUIET_OPTS = ["-q", "--no-tty", "--batch"]
GPG_FD_OPTS = ["--command-fd", "0", "--status-fd", "1"]

ACCEPTABLE_WHITESPACE_RE = r"[ \t\n]"
# Match whole key blcoks
KEY_RE = re.compile(
    r"(-----BEGIN PGP PUBLIC KEY BLOCK-----\n.*-----END PGP"
    " PUBLIC KEY BLOCK-----)",
    re.DOTALL,
)
# Match fill fingerprints
FP_RE = re.compile(r"((?:[\dA-Fa-f]{4}" + ACCEPTABLE_WHITESPACE_RE + r"*){10})")
# Match uids in the form of `name <email>`
UID_RE = re.compile(r"(.*) <(.*)>$")

# Fix up RE: removing leading quotes
FIXNAME1_RE = re.compile(r'^[\'"]')
# Fix up RE: removing trailing quotes
FIXNAME2_RE = re.compile(r'[\'"]$')
# Fix up RE: Squash whitespace in FPs.
FIXFP_RE = re.compile(ACCEPTABLE_WHITESPACE_RE + r"+")

# Note the line with the email address on it below is intentionally
# shorter than the rest to give it space to grow and still be < 80.
DEFAULT_MIME_EMAIL_TEXT = """Hello,

Attached is a copy of your PGP key (0x%(keyid)s) signed by my key
(0x%(signer)s).

If your key has more than one UID, then this key only has the UID associated
with this email address (%(email)s) signed and you will receive
additional emails containing signatures of the other UIDs at the respective
email addresses.

Please take the attached message and decrypt it and then import it.
Something like this should work:

   gpg --import <file>

(In mutt ctrl-k will do this.)

Then, don't forget to send it to a keyserver:

   gpg --keyserver keys.openpgp.org --send-key %(keyid)s

If you have any questions, let me know.


Generated by PIUS (http://www.phildev.net/pius/).
"""

DEFAULT_NON_MIME_EMAIL_TEXT = """Hello,

Attached is a copy of your PGP key (0x%(keyid)s) signed by my key
(0x%(signer)s).

If your key has more than one UID, then this key only has the UID associated
with this email address (%(email)s) signed and you will receive
additional emails containing signatures of the other UIDs at the respective
email addresses.

Please take the attached message and decrypt it and then import it.
Something like this should work:

   gpg -d <file> | gpg --import

Then, don't forget to send it to a keyserver:

   gpg --keyserver keys.openpgp.org --send-key %(keyid)s

If you have any questions, let me know.


Generated by PIUS (http://www.phildev.net/pius/).
"""

CERT_LEVEL_INFO = """Each certification level means something specific and is a
public statement by you about this UID on this key. The following definitions
are taken from the GnuPG man page.

0   means you make no particular claim as to how carefully you verified the
    key.

1   means you believe the key is owned by the person who claims to own it but
    you could not, or did not verify the key at all. This is useful for a
    "persona" verification, where you sign the key of a pseudonymous user.

2   means you did casual verification of the key. For example, this could mean
    that you verified the key fingerprint and checked the user ID on the key
    against a photo ID.

3   means you did extensive verification of the key. For example, this could
    mean that you verified the key fingerprint with the owner of the key in
    person, and that you checked, by means of a hard to forge document with a
    photo ID (such as a passport) that the name of the key owner matches the
    name in the user ID on the key, and finally that you verified (by exchange
    of email) that the email address on the key belongs to the key owner.

Note that the examples given above for levels 2 and 3 are just that: examples.
In the end, it is up to you to decide just what "casual" and "extensive" mean to
you."""
