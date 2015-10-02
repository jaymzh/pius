# PIUS Report

## Introduction

After you do all the work to go to keysigning party and then sign all the keys,
it's frustrating when other's don't do it. Nagging people manually is very time
consuming and pius-report makes that easier.

It will determine who needs to do what and send then a kind reminder.

## Usage

```
pius-report -r <keyring> -p "My Party"
```

This will do several things:
1. Refresh all keys on that keyring (to ensure anyone who has uploaded signatures
  you sent them are accounted for)
2. Cross reference all signatures to and from you to determine who didn't sign whom
3. For keys missing your signature you will get three options
  * Assume all keys not signed were on purpose[1]
  * Ask about each key, and save the results (in ~/.pius/)
  * Assume you need to sign all such keys[1]
4. Then it will prompt before emailing:
  * everyone who hasn't signed your key and remind them to do so
  * everyone you said you signed but the signature wasn't found and remind
    them to upload your key

[1] If you choose to assume all keys were not signed on purpose *or* that all
all such keys need to be signed then you won't email people who forgot to upload
signatures you sent them to remind them to do so.


vim:shiftwidth=2:tabstop=2:expandtab:textwidth=80:softtabstop=2:ai:
