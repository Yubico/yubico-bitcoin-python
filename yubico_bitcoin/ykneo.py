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

import struct
import re
from smartcard.System import readers
from yubico_bitcoin.exc import (NoKeyLoadedException, PINModeLockedException,
                                IncorrectPINException)


__all__ = [
    'open_key',
    'YkneoBitcoin'
]


READER_PATTERN = re.compile('.*Yubikey NEO.*')


def require_user(orig):
    def new_func(neo, *args, **kwargs):
        if not neo.user_unlocked:
            raise PINModeLockedException(False)
        return orig(neo, *args, **kwargs)
    return new_func


def require_admin(orig):
    def new_func(neo, *args, **kwargs):
        if not neo.admin_unlocked:
            raise PINModeLockedException(True)
        return orig(neo, *args, **kwargs)
    return new_func


def require_key(orig):
    def new_func(neo, *args, **kwargs):
        if not neo.key_loaded:
            raise NoKeyLoadedException()
        return orig(neo, *args, **kwargs)
    return new_func


def hex2cmd(data):
    return map(ord, data.decode('hex'))


def pack_path(path):
    return ''.join([struct.pack('>I', index) for index in
                    [int(i[:-1]) | 0x80000000 if i.endswith("'") else int(i)
                     for i in path.split('/')]])


def open_key(name=None):
    """
    Opens a smartcard reader matching the given name and connects to the
    ykneo-bitcoin applet through it.

    Returns a reference to the YkneoBitcoin object.
    """
    r = re.compile(name) if name else READER_PATTERN
    for reader in readers():
        if r.match(reader.name):
            conn = reader.createConnection()
            conn.connect()
            return YkneoBitcoin(conn)
    raise Exception('No smartcard reader found matching: %s' % r.pattern)


class YkneoBitcoin(object):

    """
    Interface to the ykneo-bitcoin applet running on a YubiKey NEO.

    Extended keys used are in the
    <a href="https://en.bitcoin.it/wiki/BIP_0032">BIP 32</a> format.
    A single extended key pair is stored on the YubiKey NEO, which is used to
    derive sub keys used for signing.

    BIP 32 supports a tree hierarchy of keys, and ykneo-bitcoin supports
    accessing these sub keys for use in the get_public_key and sign methods.
    Private key derivation is supported, by setting the first (sign-) bit of
    index, as per the BIP 32 specification.

    Example:
    neo = new YkneoBitcoin(...)
    master_key = ...
    neo.import_extended_key_pair(master_key, False)
    # neo now holds the master key pair m.

    # This returns the uncompressed public key from sub key m/0/7:
    neo.get_public_key(0, 7)

    # This returns the signature of hash signed by m/1/4711':
    neo.sign(1, 4711 | 0x80000000, hash)
    """

    def __init__(self, reader):
        self.reader = reader
        self._user_unlocked = False
        self._admin_unlocked = False

        data, status = self._cmd(0, 0xa4, 0x04, 0x00,
                                 'a0000005272102'.decode('hex'))
        if (status) != 0x9000:
            raise Exception('Unable to select the applet')

        self._version = tuple(data[0:3])
        self._key_loaded = data[3] == 1

    @property
    def user_unlocked(self):
        return self._user_unlocked

    @property
    def admin_unlocked(self):
        return self._admin_unlocked

    @property
    def version(self):
        return "%d.%d.%d" % self._version

    @property
    def key_loaded(self):
        return self._key_loaded

    def _cmd(self, cl, ins, p1, p2, data=''):
        command = '%02x%02x%02x%02x%02x%s' % (cl, ins, p1, p2, len(data),
                                              data.encode('hex'))
        data, sw1, sw2 = self.reader.transmit(hex2cmd(command))
        return data, sw1 << 8 | sw2

    def _cmd_ok(self, *args, **kwargs):
        data, status = self._cmd(*args, **kwargs)
        if status != 0x9000:
            raise Exception('APDU error: 0x%04x' % status)
        return ''.join(map(chr, data))

    def unlock_user(self, pin):
        _, status = self._cmd(0, 0x21, 0, 0, pin)
        if status == 0x9000:
            self._user_unlocked = True
        elif status & 0xfff0 == 0x63c0:
            self._user_unlocked = False
            raise IncorrectPINException(False, status & 0xf)
        else:
            raise Exception('APDU error: 0x%04x' % status)

    def unlock_admin(self, pin):
        _, status = self._cmd(0, 0x21, 0, 1, pin)
        if status == 0x9000:
            self._admin_unlocked = True
        elif status & 0xfff0 == 0x63c0:
            self._admin_unlocked = False
            raise IncorrectPINException(True, status & 0xf)
        else:
            raise Exception('APDU error: 0x%04x' % status)

    def _send_set_pin(self, old_pin, new_pin, admin):
        data = chr(len(old_pin)) + old_pin + chr(len(new_pin)) + new_pin
        _, status = self._cmd(0, 0x22, 0, 1 if admin else 0, data)
        return status

    def set_admin_pin(self, old_pin, new_pin):
        status = self._send_set_pin(old_pin, new_pin, True)
        if status == 0x9000:
            self._admin_unlocked = True
        elif status & 0xfff0 == 0x63c0:
            self._admin_unlocked = False
            raise IncorrectPINException(True, status & 0xf)
        else:
            raise Exception('APDU error: 0x%04x' % status)

    def set_user_pin(self, old_pin, new_pin):
        status = self._send_set_pin(old_pin, new_pin, False)
        if status == 0x9000:
            self._user_unlocked = True
        elif status & 0xfff0 == 0x63c0:
            self._user_unlocked = False
            raise IncorrectPINException(False, status & 0xf)
        else:
            raise Exception('APDU error: 0x%04x' % status)

    @require_admin
    def _send_set_retry_count(self, attempts, admin):
        if not 0 < attempts < 16:
            raise ValueError('Attempts must be 1-15, was: %d', attempts)

        self._cmd_ok(0, 0x15, 0, 1 if admin else 0, chr(attempts))

    def set_user_retry_count(self, attempts):
        self._send_set_retry_count(attempts, False)

    def set_admin_retry_count(self, attempts):
        self._send_set_retry_count(attempts, True)

    @require_admin
    def reset_user_pin(self, pin):
        self._cmd_ok(0, 0x14, 0, 0, pin)

    @require_admin
    def generate_master_key_pair(self, allow_export, return_private,
                                 testnet=False):
        p2 = 0
        if allow_export:
            p2 |= 0x01
        if return_private:
            p2 |= 0x02
        if testnet:
            p2 |= 0x04
        resp = self._cmd_ok(0, 0x11, 0, p2)
        self._key_loaded = True
        return resp

    @require_admin
    def import_extended_key_pair(self, serialized_key, allow_export):
        self._cmd_ok(0, 0x12, 0, 1 if allow_export else 0, serialized_key)
        self._key_loaded = True

    @require_admin
    def export_extended_public_key(self):
        return self._cmd_ok(0, 0x13, 0, 0)

    @require_user
    @require_key
    def get_public_key(self, path):
        return self._cmd_ok(0, 0x01, 0, 0, pack_path(path))

    @require_user
    @require_key
    def sign(self, path, digest):
        if len(digest) != 32:
            raise ValueError('Digest must be 32 bytes')
        return self._cmd_ok(0, 0x02, 0, 0, pack_path(path) + digest)

    @require_user
    @require_key
    def get_header(self):
        return self._cmd_ok(0, 0x03, 0, 0)
