#!/usr/bin/python

import subprocess
import struct
from u2flib_host import u2f
import os
import pyasn1.codec.der.decoder
import OpenSSL.crypto

U2F_REGISTER = 0x01
U2F_AUTHENTICATE = 0x2
U2F_VERSION = 0x03

SSH_U2F_APP = struct.pack('<32s', b'u2f@openssh.org')

ISO7816_3_LE_UNLIMITED = 'unlimited'

# Notes on ISO 7816-3: there are two relevant lengths and four "cases".
# The lengths are Lc and Le.  Lc is the length of the command's data
# portion and Le is rather something vaguely resembling the length
# of the expected response.  Le has a special case in that indicates
# that a reponse is expected but that the length is unspecified; that
# case is coded as '\x00\x00', but we call it ISO7816_3_LE_UNLIMITED
# to avoid confusision with the actual zero case.
#
# Note that there are protocols (e.g. U2F) that simply don't use Le.
#
# I'm paraphrasing quite a bit from the spec.  The spec is not very
# comprehensible
#
# The cases are:
# Case 1: Lc == 0, Le == 0
# Case 2: Lc == 0, Le != 0
# Case 3: Lc != 0, Le == 0
# Case 4: Lc != 0, Le != 0
#
# Cases 2-4 come in "short" and "extended" variants.  An extended APDU
# is distinguished from a short APDU by having its fifth byte set to
# zero.

def _iso7816_3_check_types(cla, ins, p1, p2, data):
    for val in (cla, ins, p1, p2):
        if val != int(val):
            raise TypeError('ISO 7816-3 byte parameters must integers')
        if val < 0 or val > 255:
            raise ValueError('ISO 7816-3 byte parameters are out of range')

    if not isinstance(data, bytes):
        raise TypeError('ISO 7816-3 payload must be bytes')

def iso7816_3_encode_short(cla, ins, p1, p2, data, le):
    _iso7816_3_check_types(cla, ins, p1, p2, data)

    if len(data) > 255:
        raise ValueError('ISO 7816-3 short payload is limited to 255 bytes')

    if le != ISO7816_3_LE_UNLIMITED and (le < 0 or le > 255):
        raise ValueError('ISO 7816-3 Le is out of range')

    prefix = struct.pack('>BBBB', cla, ins, p1, p2)

    if len(data) == 0:
        # Case 1 or 2
        all_but_le = prefix
    else:
        # Case 3 or 4
        all_but_le = prefix + struct.pack('>B', len(data)) + data

    if le == 0:
        return all_but_le # Case 1 or 3
    else:
        if le == ISO7816_3_LE_UNLIMITED:
            return all_but_le + b'\x00'
        else:
            return all_but_le + struct.pack('>B', le)

def iso7816_3_encode_extended(cla, ins, p1, p2, data, le):
    _iso7816_3_check_types(cla, ins, p1, p2, data)

    if len(data) > 65535:
        raise ValueError('ISO 7816-3 extended payload is limited to 65535 bytes')

    if le != ISO7816_3_LE_UNLIMITED and (le < 0 or le > 65535):
        raise ValueError('ISO 7816-3 Le is out of range')

    le_code = le if le != ISO7816_3_LE_UNLIMITED else 0

    if len(data) == 0:
        if le == 0:
            # Case 1 extended is the same as case 1 short
            return struct.pack('>BBBB', cla, ins, p1, p2)
        else:
            # Case 2E omits the Lc field entirely.  This only makes sense
            # because Lc == 0 in an extended APDU is impossible if Le == 0,
            # as that type of APDU is always encoded as a short APDU.
            return struct.pack('>BBBBBH', cla, ins, p1, p2, 0, le_code)
    else:
        all_but_le = struct.pack('>BBBBBH', cla, ins, p1, p2, 0,
                                 len(data)) + data
        if le == 0:
            # Case 3E
            return all_but_le
        else:
            return all_but_le + struct.pack('>H', le_code)

class Parser(object):
    def __init__(self, data):
        self.data = data

    def parse_bytes(self, size):
        if size > len(self.data) or size < 0:
            raise ValueError('malformed data')
        ret = self.data[:size]
        self.data = self.data[size:]
        return ret

    def parse_struct(self, fmt):
        s = struct.Struct(fmt)
        return s.unpack(self.parse_bytes(s.size))

    def parse_asn1der_rawdata(self):
        parsed = pyasn1.codec.der.decoder.decode(self.data)
        size = len(self.data) - len(parsed[1])
        return self.parse_bytes(size)

    def parse_rest(self):
        return self.parse_bytes(len(self.data))

    def parse_end(self):
        if len(self.data) != 0:
            raise ValueError('malformed data')

class Key(object):
    __slots__ = ['challenge', 'app', 'pubkey', 'handle', 'cert', 'sig']

    def attestation_sig_data(self):
        """Returns the data that the attestation cert should have signed."""
        return (struct.pack('>B32s32s', 0x00, self.app, self.challenge) +
                self.handle + self.pubkey)

    def has_well_formed_attestation(self):
        """This returns True if the attestation is validly signed
        by the attestation certificate and matches the key and challenge.
        Otherwise it return False.

        Note that a True return does not check whether the attestation
        certificate itself is valid.  Anyone can easily build a fake
        or malicious U2F token that will nonetheless cause this method
        to return True.
        """
        try:
            x509 = OpenSSL.crypto.load_certificate(
                OpenSSL.crypto.FILETYPE_ASN1, self.cert)
            OpenSSL.crypto.verify(x509, self.sig,
                                  self.attestation_sig_data(), 'sha256')
            return True
        except OpenSSL.crypto.Error:
            return False

class Authentication(object):
    __slots__ = ['presence', 'counter', 'sig']

def u2freq(ins, p1, p2, msg):
    with u2f.list_devices()[0] as d:
        return d.send_apdu(ins, p1, p2, msg)

_PUBKEY_HEADER = struct.Struct('<B65sB')

def generate_key():
    challenge = os.urandom(32)
    app = SSH_U2F_APP
    regmsg = challenge + app
    result = u2freq(U2F_REGISTER, 0, 0, regmsg)

    p = Parser(result)

    zerofive, pubkey, khlen = p.parse_struct('<B65sB')
    if zerofive != 0x05:
        raise ValueError('malformed data')
    kh = p.parse_bytes(khlen)
    cert = p.parse_asn1der_rawdata()
    sig = p.parse_asn1der_rawdata()
    p.parse_end()

    key = Key()
    key.challenge = challenge
    key.app = SSH_U2F_APP
    key.pubkey = pubkey
    key.handle = kh
    key.cert = cert
    key.sig = sig

    return key

def authenticate(handle, app, challenge):
    regmsg = struct.pack('>32s32sB', challenge, app, len(handle)) + handle

    # P1 = 0x03 means "enforce user presence and sign"
    result = u2freq(U2F_AUTHENTICATE, 0x03, 0, regmsg)

    p = Parser(result)

    ret = Authentication()
    ret.presence, ret.counter = struct.unpack('>BI', p.parse_bytes(5))
    ret.sig = p.parse_asn1der_rawdata()
    p.parse_end()
    return ret

def main():
    print(generate_key())

if __name__ == '__main__':
    main()
