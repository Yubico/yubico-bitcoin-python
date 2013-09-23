# Copyright (c) 2013 Yubico AB
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#    1. Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#    2. Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

__all__ = [
    'NoKeyLoadedException',
    'PINModeLockedException',
    'IncorrectPINException'
]


class YkneoError(Exception):
    pass


class NoKeyLoadedException(YkneoError):

    def __init__(self):
        super(NoKeyLoadedException, self).__init__(
            'No master key has been loaded onto the device')


class PINModeLockedException(YkneoError):

    def __init__(self, admin):
        super(PINModeLockedException, self).__init__(
            'The requested action required %s mode to be unlocked' %
            ('admin' if admin else 'user'))
        self._admin = admin

    @property
    def admin(self):
        return self._admin


class IncorrectPINException(YkneoError):

    def __init__(self, admin, tries_remaining):
        super(IncorrectPINException, self).__init__(
            'Incorrect PIN for %s, %d attempts remaining' %
            ('admin' if admin else 'user', tries_remaining))
        self._admin = admin
        self._tries = tries_remaining

    @property
    def admin(self):
        return self._admin

    @property
    def tries_remaining(self):
        return self._tries
