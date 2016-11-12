# gpg-sign-tool: renamed from quickpgp 

Set the following:
```
    KEY_USE_NAME    : the user name may be human readable - including spaces
    KEY_USE_COMMENT : the key use comment
    KEY_USE_EMAIL   : the full email address
```
TODO

- look at adding a keyring (example 1)[https://gist.github.com/stuart-warren/93750a142d3de4e8fdd2] (example 2)[https://gist.github.com/eliquious/9e96017f47d9bd43cdf9]

```
https://gist.github.com/jyap808/8250067
https://gist.github.com/jyap808/8250124
```

`gpg-sign-tool` is a simple tool for executing common subset of key
operations. It demonstrates some golang openpgp operations.

## Purpose

GPG assumes you're going to be part of a massive public key infrastructure, with support for multiple keys, kept on keyrings, signed by third parties, shared via keyservers, chosen by key IDs. blah blah blah.

However, you're subject to a requirement to regularly send someone a PGP signed file, where the public key has been shared out-of-band.  This often comes up as part of some convoluted EDI process.

And, of course, you want your end of this to be automated.  You want the key to live with the process, not in the home directory of the (system or real) user who happens to be invoking the process.  And you want this process to maintain keys separately from your user keys and keyrings, which you use for other purposes.

Maintaining a PGP "home directory" for keyring storage is slightly too complicated.  Some combination of options always seems to make a `~/.gnupg` no matter what you do.  And if this exists, sometimes keyrings in it get search/included even if you don't want them to be.  There *is* a way to use `gpg` in a batch and "immediate" mode, but it's not straight forward.  So you end up with stuff like [gpg-tmp](https://github.com/Keith-S-Thompson/gpg-tmp).  Which mostly works, except when it doesn't.  And then there's having to remember to ASCII armor your keys.  And backing up the imported keyrings.

`gpg-sign-tool` gets rid of all that.  Sometimes, you just want to sign a file with a key you have right there.

## Compliation

```
$ make
```

## Usage

### Create a key pair

This is not strictly necessary, since you can also use files containing keys extracted from a regular opengpg/pgp keyring.

```
$ gpg-sign-tool genkey bedrock
$ ls -l bedrock*
-rw------- 1 fred flintstones  3457 Jan  1  1961 bedrock.key.asc
-rw-rw-r-- 1 fred flintstones  1692 Aug  1  1961 bedrock.pub.asc
```
Produces `bedrock.key.asc` and `bedrock.pub.asc`.

By default, it will use `LOGNAME`, `COMMENT` (usually empty), and `HOSTNAME` from the environment in order to set the identity of the key.

```
$ LOGNAME=neo \
  COMMENT="follow the white rabbit" \
  HOSTNAME="nebuchadnezzar.example.com" \
  gpg-sign-tool genkey matrix
$ ls -l matrix*
-rw------- 1 neo theone        3457 Mar 31  1999 matrix.key.asc
-rw-rw-r-- 1 neo theone        1692 Mar 31  1999 matrix.pub.asc
```

### Sign a file

```
$ gpg-sign-tool sign file bedrock.key.asc
```

Produces `file.asc`, containing the detached signature.

### Verify a signature

```
$ gpg-sign-tool verify file bedrock.pub.asc
```
This will output either an error message or `Good signature from "<identity>"` on stderr.  The exit code will be 0 if the signature is good.


### Get information about a key file

Shows information about the key.  The format is similar to the output of `gpg --list-[secret-]keys`.
```
$ gpg-sign-tool indentify matrix.key.asc
matrix.key.asc
--------------
sec   2048 /DF2FE68C75DF3663 1999-03-31T00:00:01Z
      Key fingerprint = DD5D AC8C C901 8142 9F39  3760 DF2F E68C 75DF 3663

pub   2048 /DF2FE68C75DF3663 1999-03-31T00:00:01Z
      Key fingerprint = DD5D AC8C C901 8142 9F39  3760 DF2F E68C 75DF 3663
uid                          neo (follow the white rabbit) <neo@nebuchadnezzar.example.com>
sub   2048 /831D828900A7CB9A 1999-03-31T00:00:01Z

$ gpg-sign-tool identify matrix.pub.asc 
matrix.pub.asc
--------------
pub   2048 /DF2FE68C75DF3663 1999-03-31T00:00:01Z
      Key fingerprint = DD5D AC8C C901 8142 9F39  3760 DF2F E68C 75DF 3663
uid                          neo (follow the white rabbit) <neo@nebuchadnezzar.example.com>
sub   2048 /831D828900A7CB9A 1999-03-31T00:00:01Z
```
