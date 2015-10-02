# PIUS Keyring Manager

## Introduction

The PIUS Keyring Manager is a tool for people organizing a keysigning party. It
vastly simplifies the process.

If you host large PGP Keysigning Parties, manually building the keyring can be
a huge pain. This utility can be pointed at an mbox or CSV file and will find
keys or fingerprints, attempt to find keys on keyservers, and email users whose
keys cannot be found.

It is the primary tool I use for managing the SCALE PGP Keysigning party as of
2011.

## Usage

### Building the keyring

Typically usage would be to save incoming "RSVP"s (keys and fingerprints that
have been emailed to you), to an mbox folder and then:

```
pius-keyring-mgr build -r <path_to_keyring> \
  -b <path_to_mbox> -m <your_email> -p "Party Name"
```

This will:
* Find all keys in the mbox and import them to the keyring
* Find all fingerprints in the mbox and attempt to find them on a keyserver and
import them.
* Email any user who sent a fingerprint whose key cannot be found on a keyserver

If you're using a system that takes registrations from a web form and can get a
CSV of information you can have pius-keyring-mgr parse that by passing in:

```
pius-keyring-mgr build -r <path_to_keyring> \
  -b <path_to_mbox> -m <your_email> -p "Party Name" \
  --csv-file <path_to_csv> -D, -E4 -F5 -N3
```

The extra options tell pius-keyring-mgr how to parse your CSV file:

* `-D` is the delimeter
* `-E` is the field with the user's email
* `-F` is the field with the user's fingerprint
* `-N` is the field with the user's name

pius-keyring-mgr is smart enough to be run multiple times on the same keyring
with a growing mbox or CSV file and do the right thing.

Sometimes you may want to stop emailing certain users for some reason, and you
can pass in `--ignore-emails` or `--ignore-fingerprints`.

### Pruning the keyring

Once the party is over and you want to make the keyring available, you'll want
to run the 'prune' option which will prompt you for each key on the keyring if
the person was in attendance. This is so you can prune all the no-shows from
the keyring and make it easier for people to use PIUS with your keyring.

```
pius-keyring-mgr prune -r <path_to_keyring>
```

### Raw mode

Sometimes you may need to do some extra stuff to the keyring. You *could* just
use gpg directly on the keyring, but pius-keyring-mgr does a lot of work to keep
that keyring from having any effect on your primary keyring or trustdb, so we
provide a nice way to use gpg directly through pius-keyring-manager. You can
pass any set of options to the `raw` mode like so:

```
pius-keyring-manager raw -r path/to/keyring.gpg -- --recv-key <keyid>
```

Everything after the `--` is passed directly to gpg.


Phil Dibowitz
phil@ipom.com

# vim:shiftwidth=2:tabstop=2:expandtab:textwidth=80:softtabstop=2:ai:
