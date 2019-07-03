class AgentError(Exception):
    """An exception for when Agent sucks."""

    pass


class PassphraseError(Exception):
    """An exception for when a 'good' cached passphrase didn't work."""

    pass


class NoSelfKeyError(Exception):
    """An exception for when the user didn't include their own public key in the
  keyring."""

    pass


class EncryptionKeyError(Exception):
    """An exception for when a key can't encrypt (no encryption subkey)."""

    pass


class EncryptionUnknownError(Exception):
    """An exception for NOT the above. Should never happen."""

    pass


class GpgUnknownError(Exception):
    """An exception for NOT the above. Should never happen."""

    pass


class MailSendError(Exception):
    """An exception for for NOT the above. Should never happen."""

    pass
