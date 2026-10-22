"""Explicit, process-local bcrypt acceleration for disposable browser fixtures."""

import bcrypt


_original_gensalt = bcrypt.gensalt


def enable_fast_password_hashing():
    """Use real bcrypt with cost four only after the E2E fixture opts in."""
    def fast_gensalt(rounds=12, prefix=b'2b'):
        del rounds
        return _original_gensalt(rounds=4, prefix=prefix)

    bcrypt.gensalt = fast_gensalt
