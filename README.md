# PIUS: The PGP Individual UID Signer

[![Unittest](https://github.com/jaymzh/pius/actions/workflows/unit.yml/badge.svg)](https://github.com/jaymzh/pius/actions/workflows/unit.yml)

## Introduction

Signing keys after a PGP Keysigning party can take a lot of time. Further,
it's very difficult to do **right**: signing each UID separately and emailing it
off is not something tools make easy. I wanted to solve both of those problems
and make signing keys the right and most secure way easier and faster. PIUS and
its related tools make this process simple, faster, and easier to get right.

## Installation

PIUS is packaged in a wide variety of distributions; the table below lists them.
If your distribution or OS is listed, using the included package manager is by
far the easiest method of installation. 

[![Packaging status](https://repology.org/badge/vertical-allrepos/pius.svg?exclude_unsupported=1)](https://repology.org/project/pius/versions)

If PIUS isn't available for your OS or distribution, see the `INSTALL` file for
instructions on installing from source.

## Usage

The most common way to use PIUS is with a keyring from a keysigning party, like
this:

```
$ pius -A -s <your_keyid> -r <path_to_keyring> -m <your_email>
```

For every key (`-A`) on the keyring (`-r`) this will prompt you to verify the
fingerprint and choose a signing level. Then, if you tell it to, it will sign
all UIDs on &lt;keyid&gt;, and export one copy of the key for each UID with
only that UID signed. Each one will then be encrypt-emailed off to the email
address in the UID (`-m`). Finally, `-s` tells it which key to sign with.

There are a variety of other options that you may want:
* customize the tmpdir and outdir directories (-t and -o respectively)
* encrypt the outfiles to &lt;filename&gt;_ENCRYPTED.asc (-e)
* import the unsigned keys to the default keyring (-I)
* verbose mode (-v)
* customize mail hostname and port (-H and -P respectively)
* customize the email message (-M)
* don't use PGP/Mime in the email (-O, implies -e)
* specify SMTPAUTH (-u) and either STARTTLS (-S) or SSL (--ssl) for SMTP

And more! See the '-h' option for more.


## Security Implications

As of 3.0, PIUS only works with gpg2 and later, and thus only works
with a GPG Agent. Therefore, PIUS can never come into contact with your
passphrase or your unencrypted private key.


## Sending Emails

When PIUS emails out keys it BCC's you, so you will get a copy of every email
sent out. If you would like to see what is going to be sent and not have it
sent, you can either do:

```
$ pius -T
```

To have PIUS dump the text of the default email body, or you can use the -n
option to forcefully override the TO in the envelope of the email. When doing
this *only* the address specified as an argument to `-n` will get the email.

If you want to see the email sent when not using PGP/Mime then try:

```
$ pius -T -O
```

If you want to customize this message you can do so with the -M option. Note
that you may use python's named variable interpolation syntax here to have PIUS
fill in email (the email in the UID, i.e. the recipient), keyid (of the key that
was signed), and signer (the keyid used to sign, i.e. your keyid). For example,
you can simply include "%(keyid)s" (without the quotes) to get the keyid.

PIUS's default config assumes there is a local mail delivery agent (MDA)
available on port 587. If this is not the case for you, you'll want to specify
your mail server's information using `-H` for smtp host, `-P` for port, and `-u`
for username. For example, for GMail you might use:

```
-H smtp.gmail.com -P 587 -u <your_email@gmail.com>
```

I recommend you add these settings to your config file so you don't have to type
them every time. See the [Config File](#config-file) section below.

Note that if you've setup 2-factor authentication with your mail provider, you
will need an app-password for this to work. For GMail, [see their
docs](https://support.google.com/accounts/answer/185833?hl=en).


## Other Platforms

On non-UNIX platforms such as MacOS and Windows, the default gpg path will
likely be incorrect, so you'll want to use `-b` to specify the path.


## Config File

You can specify options you'd like to always use in a ~/.pius/piusrc file. The
format of this file is option=value. The "=value" part is obviously not required
for options that don't have a value. An example might be:

```
mail=you@sample.com
tmp-dir=/home/you/pius/tmp
use-agent
```

PIUS will accept `=`, `:` or whitespace as a separator, and will handle
extra whitespace around any separator.


## History

PIUS started life as a group of bad shell scripts I had thrown together through
the years after going to various PGP keysigning parties. These scripts
automated various bits and pieces of signing various keys and UIDs, but fell
short of actually making it a mostly painless process.

Finally I decided to sit down and combine all these shell scripts into a single
unified utility to make signing individual UIDs on a multitude of keys as
painless as possible. Since this was going to be mostly forking off gpg
instances, it seemed like shell was the way to go. However, after dealing with
gpg and its "API" for a while, I quickly realized that was not going to be the
best course of action. Since I wanted an excuse to write more python, instead
of my usual perl, I decided to write this in python.

The original version heavily used the pexpect module for various reasons: (1) I
wanted to be able to let the user enter the passphrase directly into gpg for
security reasons, (2) Using the --{command,passphrase,status}-fd options turned
not to be not that well documented and not work the way the documentation
suggested.

This method quickly showed itself to be very fragile. So, I managed to bend gpg
to my will without using pexpect, and the only thing left that uses pexpect was
the 'interactive' mode, which has been removed now that gpg-agent is both
required in gpg 2.x and stable.


## License

PIUS is released under the GNU Public License v2 and is Copyright `Phil Dibowitz
<phil@ipom.com>`.


Phil Dibowitz

phil@ipom.com

vim:shiftwidth=2:tabstop=2:expandtab:textwidth=80:softtabstop=2:ai:
