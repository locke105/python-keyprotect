from __future__ import absolute_import

# alias keyprotect -> keyprotect.keyprotect
# keeps the keyprotect.py module as copy-able single file,
# but we can package it in its own namespace as an installable as well
from keyprotect.keyprotect import *  # noqa: F401,F403
