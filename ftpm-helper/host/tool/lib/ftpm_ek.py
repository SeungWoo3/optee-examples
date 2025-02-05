# Copyright (c) 2023, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause

from Cryptodome.PublicKey.RSA import RsaKey
from Cryptodome.Math.Numbers import Integer
from ecdsa import SigningKey, util
import numpy as np

class EC_Gen_Key:
    def __init__(self, curve, rand_func):
        self.curve = curve
        self.rand_rand_func = rand_func

    # This function uses the method defined in FIPS 186-4,
    # section B.4.1 Key Pair Generation Using Extra Random Bits,
    # to generate an ECDSA private key.
    def gen_ecdsa_keypair_by_extra_random_bits(self, curve, rand_func):
        _req_seed_len = util.orderlen(curve.order) + 8

        _extra_random = rand_func(_req_seed_len)
        _minus_1 = curve.order - 1
        _extra_random = int(_extra_random.hex(), 16) % _minus_1
        _d = _extra_random + 1
        _d_hex = _d.to_bytes(util.orderlen(curve.order), byteorder='big')

        _ec_priv_key = SigningKey.from_string(_d_hex, curve)
        _ec_pub_key = _ec_priv_key.get_verifying_key()

        return _ec_priv_key.to_der(), _ec_pub_key.to_der()

class RSA2K_Gen_Key:
    def __init__(self, key_len_bits, rand_func):
        self.exponent = 65537
        self.rand_func = rand_func
        self.key_size_in_bits = key_len_bits

    def generate_key_pair(self):
        q = Integer(0)
        e = Integer(self.exponent)

        for (_trial) in range(100):
            # Get p and q
            p = self._generate_prime()

            p = Integer.from_bytes(p)

            if (q == 0):
                q = p
                continue

            if (p > q):
                d = p - q
            else:
                d = q - p

            def _Msb(data):
                ret = -1
                _temp = int(data.hex(), 16)
                if (_temp & 0xffff0000):
                    ret += 16
                    _temp >>= 16
                if (_temp & 0x0000ff00):
                    ret += 8
                    _temp >>= 8
                if (_temp & 0x000000f0):
                    ret += 4
                    _temp >>= 4
                if (_temp & 0x0000000c):
                    ret += 2
                    _temp >>= 2
                if (_temp & 0x00000002):
                    ret += 1
                    _temp >>= 1
                return (ret + _temp)

            _pq_sub = d.to_bytes(d.size_in_bytes(), 'big')
            _pq_sub_msw = bytearray(4)
            _pq_sub_msw[:] = _pq_sub[0:4]
            _pq_sub_msb = _Msb(_pq_sub_msw) + ((d.size_in_bytes() // 4) - 1) * 32

            if (_pq_sub_msb < 100):
                continue
            else:
                break

        n = p * q
        lcm = (p - 1).lcm(q - 1)
        d = e.inverse(lcm)

        if (p > q):
            p, q = q, p

        u = p.inverse(q)

        self.rsa_key = RsaKey(n = n, e = e, d = d, p = p, q = q, u = u)

        return self.rsa_key.export_key(format='DER'), self.rsa_key.public_key().export_key(format='DER')

    def _generate_prime(self):
        _found = False
        _random_in_bytes = ((self.key_size_in_bits // 2) + 7) >> 3

        while (not _found):
            _prime = self.rand_func(_random_in_bytes)
            _prime = self._adjust_prime_candidate(_prime)
            _found, _prime = self._prime_select_with_sieve(_prime)

        return _prime

    def _adjust_prime_candidate(self, prime):
        _msw = bytearray(4)
        _adjusted_prime = bytearray(len(prime))

        _adjusted_prime[:] = prime[:]
        _msw[:] = prime[0:4]
        _msw = int(_msw.hex(), 16)
        _adjusted = (_msw >> 16) * 0x4AFB
        _adjusted += ((_msw & 0xFFFF) * 0x4AFB) >> 16
        _adjusted += 0xB5050000
        _adjusted = _adjusted.to_bytes(4, 'big')
        _adjusted_prime[0:4] = _adjusted[0:4]
        _adjusted_prime[len(_adjusted_prime) - 1] |= 1

        return _adjusted_prime

    def _prime_select_with_sieve(self, candidate):
        _first = bytearray(4)
        _first[:] = candidate[(len(candidate) - 4):len(candidate)]
        _first = (int(_first.hex(), 16) | 0x80000000).to_bytes(4, 'big')

        self.prime_markers_count = 6
        self.prime_markers = (8167, 17881, 28183, 38891, 49871, 60961)
        _requested_primes = 4096 # ues the first 4k primes
        _requested_primes = (_requested_primes - 1) / 1024
        self.prime_limit = self.prime_markers[int(_requested_primes)]
        self.prime_limit >>= 1

        candidate = self._prime_sieve(candidate)
        _candidate_int = int(candidate.hex(), 16)

        _ones = self.bits_in_field_after_sieve

        while (_ones > 0):
            _n = (int(_first.hex(), 16) % _ones) + 1
            _chosen = self._find_nth_set_bit(_n)

            # Set the trial prime
            _test = _candidate_int + (_chosen * 2)
            _mod_e = _test % self.exponent

            if ((_mod_e != 0) and (_mod_e  != 1)):
                if (self._miller_rabin_test(_test)):
                    return True, _test.to_bytes(len(candidate), 'big')

            self._clear_bit_in_field(_chosen)
            _ones -= 1

        return False, candidate

    def _prime_sieve(self, candidate):
        _candidate_int = int(candidate.hex(), 16)
        self.field = bytearray(2048)
        _field_size = len(self.field)
        _field_size_in_bits = _field_size * 8
        _seed_values_size = len(seed_values)
        _sieve_marks = np.array([[31, 7],       # prime, count
                                 [73, 5],
                                 [241, 4],
                                 [1621, 3],
                                 [65535, 2]])

        _adjust = _candidate_int % 105
        if (_adjust & 1):
            _adjust += 105
        _candidate_int -= _adjust

        _i = _field_size
        _idx = 0
        while (_i >= _seed_values_size ):
            self.field[(_idx):(_idx + _seed_values_size)] = seed_values[:_seed_values_size]
            _idx += _seed_values_size
            _i -= _seed_values_size

        if (_i != 0):
            self.field[(_idx):(_idx + _i)] = seed_values[:_i]

        def next_prime(last_prime):
            if (last_prime == 0):
                return 0
            last_prime >>= 1
            last_prime += 1
            while (last_prime <= self.prime_limit):
                if (((prime_table[last_prime >> 3] >> (last_prime & 0x7)) & 1) == 1):
                    return ((last_prime << 1) + 1)
                last_prime += 1
            return 0

        _iter = 7
        _mark = 0
        _count = _sieve_marks[_mark][1]
        _stop = _sieve_marks[_mark][0]
        _list = np.arange(8, dtype = np.uintc)

        _done = False
        _iter = next_prime(_iter)
        _composite = _iter

        while (_composite != 0):
            _next = 0
            i = int(_count)
            _list[i] = _composite

            i -= 1

            while (i > 0):
                _iter = next_prime(_iter)
                _next = _iter
                _list[i] = _next

                if (_next != 0):
                    _composite *= _next
                i -= 1

            _composite = _candidate_int % _composite

            i = int(_count)
            while (i > 0):
                _next = _list[i]
                if (_next == 0):
                    _done = True
                    break

                _r = _composite % _next

                if (_r & 1):
                    _j = (_next - _r) // 2
                elif (_r == 0):
                    _j = 0
                else:
                    _j = _next - (_r // 2)

                while (_j < _field_size_in_bits):
                    self._clear_bit_in_field(_j)
                    _j += _next

                i -= 1

            if (_done):
                break

            if (_next >= _stop):
                _mark += 1
                _count = _sieve_marks[_mark][1]
                _stop = _sieve_marks[_mark][0]

            _iter = next_prime(_iter)
            _composite = _iter


        self.bits_in_field_after_sieve = bin(int(self.field.hex(), 16)).count("1")

        return _candidate_int.to_bytes(len(candidate), 'big')

    def _clear_bit_in_field(self, bit_num):
        self.field[bit_num >> 3] &= ~(1 << (bit_num & 7))

    def _find_nth_set_bit(self, n):
        _i = 0
        _sum = 0
        _ret_value = 0
        _bits_in_nibble = bytearray([0x00, 0x01, 0x01, 0x02,
                                     0x01, 0x02, 0x02, 0x03,
                                     0x01, 0x02, 0x02, 0x03,
                                     0x02, 0x03, 0x03, 0x04])

        def bits_in_byte(byte):
            return (_bits_in_nibble[byte & 0xf] + _bits_in_nibble[((byte >> 4) & 0xf)])

        while ((_i < len(self.field)) and (_sum < n)):
            _sum += bits_in_byte(self.field[_i])
            _i += 1

        _i -= 1
        _ret_value = _i * 8 - 1
        _sel = self.field[_i]
        _sum -= bits_in_byte(_sel)

        while ((_sel != 0) and (_sum != n)):
            if (_sel & 1):
                _sum += 1
            _ret_value += 1
            _sel >>= 1

        return _ret_value

    # Miller Rabin test from FIPS 186-3
    def _miller_rabin_test(self, test):
        _iter = 5   # for RSA 2K
        _wm1 = test - 1

        # _m = _wm1 / 2^_a
        _m = Integer(_wm1)
        _a = 0
        while _m.is_even():
            _m >>= 1
            _a += 1

        _m = int(_m.to_bytes().hex(), 16)
        _w_len = test.bit_length()

        for _i in range(_iter):

            _fit_random_range = False
            while (not _fit_random_range):
                _b = self.rand_func(int(_w_len / 8))
                if (not ((int(_b.hex(), 16) <= 1) or (int(_b.hex(), 16) >= _wm1))):
                    _fit_random_range = True

            _b = int(_b.hex(), 16)

            # _z = _b^_m mod test
            _z = pow(_b, _m, test)
            if _z in (1, _wm1):
                continue

            _j = 1
            while (_j < _a):
                # _z = _z^2 mod test
                _z = pow(_z, 2, test)
                _j += 1
                if _z == _wm1:
                    break
                if _z == 1:
                    return False
            else:
                return False

        return True

# The tables refer to the official TPM 2.0 reference implementation to
# implement the same RSA key generation function.
#   https://github.com/microsoft/ms-tpm-20-ref/blob/main/TPMCmd/tpm/src/crypt/CryptPrimeSieve.c
#   https://github.com/microsoft/ms-tpm-20-ref/blob/main/TPMCmd/tpm/src/crypt/PrimeData.c

seed_values = (
    0x16, 0x29, 0xcb, 0xa4, 0x65, 0xda, 0x30, 0x6c, 0x99, 0x96,
    0x4c, 0x53, 0xa2, 0x2d, 0x52, 0x96, 0x49, 0xcb, 0xb4, 0x61,
    0xd8, 0x32, 0x2d, 0x99, 0xa6, 0x44, 0x5b, 0xa4, 0x2c, 0x93,
    0x96, 0x69, 0xc3, 0xb0, 0x65, 0x5a, 0x32, 0x4d, 0x89, 0xb6,
    0x48, 0x59, 0x26, 0x2d, 0xd3, 0x86, 0x61, 0xcb, 0xb4, 0x64,
    0x9a, 0x12, 0x6d, 0x91, 0xb2, 0x4c, 0x5a, 0xa6, 0x0d, 0xc3,
    0x96, 0x69, 0xc9, 0x34, 0x25, 0xda, 0x22, 0x65, 0x99, 0xb4,
    0x4c, 0x1b, 0x86, 0x2d, 0xd3, 0x92, 0x69, 0x4a, 0xb4, 0x45,
    0xca, 0x32, 0x69, 0x99, 0x36, 0x0c, 0x5b, 0xa6, 0x25, 0xd3,
    0x94, 0x68, 0x8b, 0x94, 0x65, 0xd2, 0x32, 0x6d, 0x18, 0xb6,
    0x4c, 0x4b, 0xa6, 0x29, 0xd1
)

prime_table = (
    0x6e, 0xcb, 0xb4, 0x64, 0x9a, 0x12, 0x6d, 0x81, 0x32, 0x4c, 0x4a, 0x86, 0x0d,
    0x82, 0x96, 0x21, 0xc9, 0x34, 0x04, 0x5a, 0x20, 0x61, 0x89, 0xa4, 0x44, 0x11,
    0x86, 0x29, 0xd1, 0x82, 0x28, 0x4a, 0x30, 0x40, 0x42, 0x32, 0x21, 0x99, 0x34,
    0x08, 0x4b, 0x06, 0x25, 0x42, 0x84, 0x48, 0x8a, 0x14, 0x05, 0x42, 0x30, 0x6c,
    0x08, 0xb4, 0x40, 0x0b, 0xa0, 0x08, 0x51, 0x12, 0x28, 0x89, 0x04, 0x65, 0x98,
    0x30, 0x4c, 0x80, 0x96, 0x44, 0x12, 0x80, 0x21, 0x42, 0x12, 0x41, 0xc9, 0x04,
    0x21, 0xc0, 0x32, 0x2d, 0x98, 0x00, 0x00, 0x49, 0x04, 0x08, 0x81, 0x96, 0x68,
    0x82, 0xb0, 0x25, 0x08, 0x22, 0x48, 0x89, 0xa2, 0x40, 0x59, 0x26, 0x04, 0x90,
    0x06, 0x40, 0x43, 0x30, 0x44, 0x92, 0x00, 0x69, 0x10, 0x82, 0x08, 0x08, 0xa4,
    0x0d, 0x41, 0x12, 0x60, 0xc0, 0x00, 0x24, 0xd2, 0x22, 0x61, 0x08, 0x84, 0x04,
    0x1b, 0x82, 0x01, 0xd3, 0x10, 0x01, 0x02, 0xa0, 0x44, 0xc0, 0x22, 0x60, 0x91,
    0x14, 0x0c, 0x40, 0xa6, 0x04, 0xd2, 0x94, 0x20, 0x09, 0x94, 0x20, 0x52, 0x00,
    0x08, 0x10, 0xa2, 0x4c, 0x00, 0x82, 0x01, 0x51, 0x10, 0x08, 0x8b, 0xa4, 0x25,
    0x9a, 0x30, 0x44, 0x81, 0x10, 0x4c, 0x03, 0x02, 0x25, 0x52, 0x80, 0x08, 0x49,
    0x84, 0x20, 0x50, 0x32, 0x00, 0x18, 0xa2, 0x40, 0x11, 0x24, 0x28, 0x01, 0x84,
    0x01, 0x01, 0xa0, 0x41, 0x0a, 0x12, 0x45, 0x00, 0x36, 0x08, 0x00, 0x26, 0x29,
    0x83, 0x82, 0x61, 0xc0, 0x80, 0x04, 0x10, 0x10, 0x6d, 0x00, 0x22, 0x48, 0x58,
    0x26, 0x0c, 0xc2, 0x10, 0x48, 0x89, 0x24, 0x20, 0x58, 0x20, 0x45, 0x88, 0x24,
    0x00, 0x19, 0x02, 0x25, 0xc0, 0x10, 0x68, 0x08, 0x14, 0x01, 0xca, 0x32, 0x28,
    0x80, 0x00, 0x04, 0x4b, 0x26, 0x00, 0x13, 0x90, 0x60, 0x82, 0x80, 0x25, 0xd0,
    0x00, 0x01, 0x10, 0x32, 0x0c, 0x43, 0x86, 0x21, 0x11, 0x00, 0x08, 0x43, 0x24,
    0x04, 0x48, 0x10, 0x0c, 0x90, 0x92, 0x00, 0x43, 0x20, 0x2d, 0x00, 0x06, 0x09,
    0x88, 0x24, 0x40, 0xc0, 0x32, 0x09, 0x09, 0x82, 0x00, 0x53, 0x80, 0x08, 0x80,
    0x96, 0x41, 0x81, 0x00, 0x40, 0x48, 0x10, 0x48, 0x08, 0x96, 0x48, 0x58, 0x20,
    0x29, 0xc3, 0x80, 0x20, 0x02, 0x94, 0x60, 0x92, 0x00, 0x20, 0x81, 0x22, 0x44,
    0x10, 0xa0, 0x05, 0x40, 0x90, 0x01, 0x49, 0x20, 0x04, 0x0a, 0x00, 0x24, 0x89,
    0x34, 0x48, 0x13, 0x80, 0x2c, 0xc0, 0x82, 0x29, 0x00, 0x24, 0x45, 0x08, 0x00,
    0x08, 0x98, 0x36, 0x04, 0x52, 0x84, 0x04, 0xd0, 0x04, 0x00, 0x8a, 0x90, 0x44,
    0x82, 0x32, 0x65, 0x18, 0x90, 0x00, 0x0a, 0x02, 0x01, 0x40, 0x02, 0x28, 0x40,
    0xa4, 0x04, 0x92, 0x30, 0x04, 0x11, 0x86, 0x08, 0x42, 0x00, 0x2c, 0x52, 0x04,
    0x08, 0xc9, 0x84, 0x60, 0x48, 0x12, 0x09, 0x99, 0x24, 0x44, 0x00, 0x24, 0x00,
    0x03, 0x14, 0x21, 0x00, 0x10, 0x01, 0x1a, 0x32, 0x05, 0x88, 0x20, 0x40, 0x40,
    0x06, 0x09, 0xc3, 0x84, 0x40, 0x01, 0x30, 0x60, 0x18, 0x02, 0x68, 0x11, 0x90,
    0x0c, 0x02, 0xa2, 0x04, 0x00, 0x86, 0x29, 0x89, 0x14, 0x24, 0x82, 0x02, 0x41,
    0x08, 0x80, 0x04, 0x19, 0x80, 0x08, 0x10, 0x12, 0x68, 0x42, 0xa4, 0x04, 0x00,
    0x02, 0x61, 0x10, 0x06, 0x0c, 0x10, 0x00, 0x01, 0x12, 0x10, 0x20, 0x03, 0x94,
    0x21, 0x42, 0x12, 0x65, 0x18, 0x94, 0x0c, 0x0a, 0x04, 0x28, 0x01, 0x14, 0x29,
    0x0a, 0xa4, 0x40, 0xd0, 0x00, 0x40, 0x01, 0x90, 0x04, 0x41, 0x20, 0x2d, 0x40,
    0x82, 0x48, 0xc1, 0x20, 0x00, 0x10, 0x30, 0x01, 0x08, 0x24, 0x04, 0x59, 0x84,
    0x24, 0x00, 0x02, 0x29, 0x82, 0x00, 0x61, 0x58, 0x02, 0x48, 0x81, 0x16, 0x48,
    0x10, 0x00, 0x21, 0x11, 0x06, 0x00, 0xca, 0xa0, 0x40, 0x02, 0x00, 0x04, 0x91,
    0xb0, 0x00, 0x42, 0x04, 0x0c, 0x81, 0x06, 0x09, 0x48, 0x14, 0x25, 0x92, 0x20,
    0x25, 0x11, 0xa0, 0x00, 0x0a, 0x86, 0x0c, 0xc1, 0x02, 0x48, 0x00, 0x20, 0x45,
    0x08, 0x32, 0x00, 0x98, 0x06, 0x04, 0x13, 0x22, 0x00, 0x82, 0x04, 0x48, 0x81,
    0x14, 0x44, 0x82, 0x12, 0x24, 0x18, 0x10, 0x40, 0x43, 0x80, 0x28, 0xd0, 0x04,
    0x20, 0x81, 0x24, 0x64, 0xd8, 0x00, 0x2c, 0x09, 0x12, 0x08, 0x41, 0xa2, 0x00,
    0x00, 0x02, 0x41, 0xca, 0x20, 0x41, 0xc0, 0x10, 0x01, 0x18, 0xa4, 0x04, 0x18,
    0xa4, 0x20, 0x12, 0x94, 0x20, 0x83, 0xa0, 0x40, 0x02, 0x32, 0x44, 0x80, 0x04,
    0x00, 0x18, 0x00, 0x0c, 0x40, 0x86, 0x60, 0x8a, 0x00, 0x64, 0x88, 0x12, 0x05,
    0x01, 0x82, 0x00, 0x4a, 0xa2, 0x01, 0xc1, 0x10, 0x61, 0x09, 0x04, 0x01, 0x88,
    0x00, 0x60, 0x01, 0xb4, 0x40, 0x08, 0x06, 0x01, 0x03, 0x80, 0x08, 0x40, 0x94,
    0x04, 0x8a, 0x20, 0x29, 0x80, 0x02, 0x0c, 0x52, 0x02, 0x01, 0x42, 0x84, 0x00,
    0x80, 0x84, 0x64, 0x02, 0x32, 0x48, 0x00, 0x30, 0x44, 0x40, 0x22, 0x21, 0x00,
    0x02, 0x08, 0xc3, 0xa0, 0x04, 0xd0, 0x20, 0x40, 0x18, 0x16, 0x40, 0x40, 0x00,
    0x28, 0x52, 0x90, 0x08, 0x82, 0x14, 0x01, 0x18, 0x10, 0x08, 0x09, 0x82, 0x40,
    0x0a, 0xa0, 0x20, 0x93, 0x80, 0x08, 0xc0, 0x00, 0x20, 0x52, 0x00, 0x05, 0x01,
    0x10, 0x40, 0x11, 0x06, 0x0c, 0x82, 0x00, 0x00, 0x4b, 0x90, 0x44, 0x9a, 0x00,
    0x28, 0x80, 0x90, 0x04, 0x4a, 0x06, 0x09, 0x43, 0x02, 0x28, 0x00, 0x34, 0x01,
    0x18, 0x00, 0x65, 0x09, 0x80, 0x44, 0x03, 0x00, 0x24, 0x02, 0x82, 0x61, 0x48,
    0x14, 0x41, 0x00, 0x12, 0x28, 0x00, 0x34, 0x08, 0x51, 0x04, 0x05, 0x12, 0x90,
    0x28, 0x89, 0x84, 0x60, 0x12, 0x10, 0x49, 0x10, 0x26, 0x40, 0x49, 0x82, 0x00,
    0x91, 0x10, 0x01, 0x0a, 0x24, 0x40, 0x88, 0x10, 0x4c, 0x10, 0x04, 0x00, 0x50,
    0xa2, 0x2c, 0x40, 0x90, 0x48, 0x0a, 0xb0, 0x01, 0x50, 0x12, 0x08, 0x00, 0xa4,
    0x04, 0x09, 0xa0, 0x28, 0x92, 0x02, 0x00, 0x43, 0x10, 0x21, 0x02, 0x20, 0x41,
    0x81, 0x32, 0x00, 0x08, 0x04, 0x0c, 0x52, 0x00, 0x21, 0x49, 0x84, 0x20, 0x10,
    0x02, 0x01, 0x81, 0x10, 0x48, 0x40, 0x22, 0x01, 0x01, 0x84, 0x69, 0xc1, 0x30,
    0x01, 0xc8, 0x02, 0x44, 0x88, 0x00, 0x0c, 0x01, 0x02, 0x2d, 0xc0, 0x12, 0x61,
    0x00, 0xa0, 0x00, 0xc0, 0x30, 0x40, 0x01, 0x12, 0x08, 0x0b, 0x20, 0x00, 0x80,
    0x94, 0x40, 0x01, 0x84, 0x40, 0x00, 0x32, 0x00, 0x10, 0x84, 0x00, 0x0b, 0x24,
    0x00, 0x01, 0x06, 0x29, 0x8a, 0x84, 0x41, 0x80, 0x10, 0x08, 0x08, 0x94, 0x4c,
    0x03, 0x80, 0x01, 0x40, 0x96, 0x40, 0x41, 0x20, 0x20, 0x50, 0x22, 0x25, 0x89,
    0xa2, 0x40, 0x40, 0xa4, 0x20, 0x02, 0x86, 0x28, 0x01, 0x20, 0x21, 0x4a, 0x10,
    0x08, 0x00, 0x14, 0x08, 0x40, 0x04, 0x25, 0x42, 0x02, 0x21, 0x43, 0x10, 0x04,
    0x92, 0x00, 0x21, 0x11, 0xa0, 0x4c, 0x18, 0x22, 0x09, 0x03, 0x84, 0x41, 0x89,
    0x10, 0x04, 0x82, 0x22, 0x24, 0x01, 0x14, 0x08, 0x08, 0x84, 0x08, 0xc1, 0x00,
    0x09, 0x42, 0xb0, 0x41, 0x8a, 0x02, 0x00, 0x80, 0x36, 0x04, 0x49, 0xa0, 0x24,
    0x91, 0x00, 0x00, 0x02, 0x94, 0x41, 0x92, 0x02, 0x01, 0x08, 0x06, 0x08, 0x09,
    0x00, 0x01, 0xd0, 0x16, 0x28, 0x89, 0x80, 0x60, 0x00, 0x00, 0x68, 0x01, 0x90,
    0x0c, 0x50, 0x20, 0x01, 0x40, 0x80, 0x40, 0x42, 0x30, 0x41, 0x00, 0x20, 0x25,
    0x81, 0x06, 0x40, 0x49, 0x00, 0x08, 0x01, 0x12, 0x49, 0x00, 0xa0, 0x20, 0x18,
    0x30, 0x05, 0x01, 0xa6, 0x00, 0x10, 0x24, 0x28, 0x00, 0x02, 0x20, 0xc8, 0x20,
    0x00, 0x88, 0x12, 0x0c, 0x90, 0x92, 0x00, 0x02, 0x26, 0x01, 0x42, 0x16, 0x49,
    0x00, 0x04, 0x24, 0x42, 0x02, 0x01, 0x88, 0x80, 0x0c, 0x1a, 0x80, 0x08, 0x10,
    0x00, 0x60, 0x02, 0x94, 0x44, 0x88, 0x00, 0x69, 0x11, 0x30, 0x08, 0x12, 0xa0,
    0x24, 0x13, 0x84, 0x00, 0x82, 0x00, 0x65, 0xc0, 0x10, 0x28, 0x00, 0x30, 0x04,
    0x03, 0x20, 0x01, 0x11, 0x06, 0x01, 0xc8, 0x80, 0x00, 0xc2, 0x20, 0x08, 0x10,
    0x82, 0x0c, 0x13, 0x02, 0x0c, 0x52, 0x06, 0x40, 0x00, 0xb0, 0x61, 0x40, 0x10,
    0x01, 0x98, 0x86, 0x04, 0x10, 0x84, 0x08, 0x92, 0x14, 0x60, 0x41, 0x80, 0x41,
    0x1a, 0x10, 0x04, 0x81, 0x22, 0x40, 0x41, 0x20, 0x29, 0x52, 0x00, 0x41, 0x08,
    0x34, 0x60, 0x10, 0x00, 0x28, 0x01, 0x10, 0x40, 0x00, 0x84, 0x08, 0x42, 0x90,
    0x20, 0x48, 0x04, 0x04, 0x52, 0x02, 0x00, 0x08, 0x20, 0x04, 0x00, 0x82, 0x0d,
    0x00, 0x82, 0x40, 0x02, 0x10, 0x05, 0x48, 0x20, 0x40, 0x99, 0x00, 0x00, 0x01,
    0x06, 0x24, 0xc0, 0x00, 0x68, 0x82, 0x04, 0x21, 0x12, 0x10, 0x44, 0x08, 0x04,
    0x00, 0x40, 0xa6, 0x20, 0xd0, 0x16, 0x09, 0xc9, 0x24, 0x41, 0x02, 0x20, 0x0c,
    0x09, 0x92, 0x40, 0x12, 0x00, 0x00, 0x40, 0x00, 0x09, 0x43, 0x84, 0x20, 0x98,
    0x02, 0x01, 0x11, 0x24, 0x00, 0x43, 0x24, 0x00, 0x03, 0x90, 0x08, 0x41, 0x30,
    0x24, 0x58, 0x20, 0x4c, 0x80, 0x82, 0x08, 0x10, 0x24, 0x25, 0x81, 0x06, 0x41,
    0x09, 0x10, 0x20, 0x18, 0x10, 0x44, 0x80, 0x10, 0x00, 0x4a, 0x24, 0x0d, 0x01,
    0x94, 0x28, 0x80, 0x30, 0x00, 0xc0, 0x02, 0x60, 0x10, 0x84, 0x0c, 0x02, 0x00,
    0x09, 0x02, 0x82, 0x01, 0x08, 0x10, 0x04, 0xc2, 0x20, 0x68, 0x09, 0x06, 0x04,
    0x18, 0x00, 0x00, 0x11, 0x90, 0x08, 0x0b, 0x10, 0x21, 0x82, 0x02, 0x0c, 0x10,
    0xb6, 0x08, 0x00, 0x26, 0x00, 0x41, 0x02, 0x01, 0x4a, 0x24, 0x21, 0x1a, 0x20,
    0x24, 0x80, 0x00, 0x44, 0x02, 0x00, 0x2d, 0x40, 0x02, 0x00, 0x8b, 0x94, 0x20,
    0x10, 0x00, 0x20, 0x90, 0xa6, 0x40, 0x13, 0x00, 0x2c, 0x11, 0x86, 0x61, 0x01,
    0x80, 0x41, 0x10, 0x02, 0x04, 0x81, 0x30, 0x48, 0x48, 0x20, 0x28, 0x50, 0x80,
    0x21, 0x8a, 0x10, 0x04, 0x08, 0x10, 0x09, 0x10, 0x10, 0x48, 0x42, 0xa0, 0x0c,
    0x82, 0x92, 0x60, 0xc0, 0x20, 0x05, 0xd2, 0x20, 0x40, 0x01, 0x00, 0x04, 0x08,
    0x82, 0x2d, 0x82, 0x02, 0x00, 0x48, 0x80, 0x41, 0x48, 0x10, 0x00, 0x91, 0x04,
    0x04, 0x03, 0x84, 0x00, 0xc2, 0x04, 0x68, 0x00, 0x00, 0x64, 0xc0, 0x22, 0x40,
    0x08, 0x32, 0x44, 0x09, 0x86, 0x00, 0x91, 0x02, 0x28, 0x01, 0x00, 0x64, 0x48,
    0x00, 0x24, 0x10, 0x90, 0x00, 0x43, 0x00, 0x21, 0x52, 0x86, 0x41, 0x8b, 0x90,
    0x20, 0x40, 0x20, 0x08, 0x88, 0x04, 0x44, 0x13, 0x20, 0x00, 0x02, 0x84, 0x60,
    0x81, 0x90, 0x24, 0x40, 0x30, 0x00, 0x08, 0x10, 0x08, 0x08, 0x02, 0x01, 0x10,
    0x04, 0x20, 0x43, 0xb4, 0x40, 0x90, 0x12, 0x68, 0x01, 0x80, 0x4c, 0x18, 0x00,
    0x08, 0xc0, 0x12, 0x49, 0x40, 0x10, 0x24, 0x1a, 0x00, 0x41, 0x89, 0x24, 0x4c,
    0x10, 0x00, 0x04, 0x52, 0x10, 0x09, 0x4a, 0x20, 0x41, 0x48, 0x22, 0x69, 0x11,
    0x14, 0x08, 0x10, 0x06, 0x24, 0x80, 0x84, 0x28, 0x00, 0x10, 0x00, 0x40, 0x10,
    0x01, 0x08, 0x26, 0x08, 0x48, 0x06, 0x28, 0x00, 0x14, 0x01, 0x42, 0x84, 0x04,
    0x0a, 0x20, 0x00, 0x01, 0x82, 0x08, 0x00, 0x82, 0x24, 0x12, 0x04, 0x40, 0x40,
    0xa0, 0x40, 0x90, 0x10, 0x04, 0x90, 0x22, 0x40, 0x10, 0x20, 0x2c, 0x80, 0x10,
    0x28, 0x43, 0x00, 0x04, 0x58, 0x00, 0x01, 0x81, 0x10, 0x48, 0x09, 0x20, 0x21,
    0x83, 0x04, 0x00, 0x42, 0xa4, 0x44, 0x00, 0x00, 0x6c, 0x10, 0xa0, 0x44, 0x48,
    0x80, 0x00, 0x83, 0x80, 0x48, 0xc9, 0x00, 0x00, 0x00, 0x02, 0x05, 0x10, 0xb0,
    0x04, 0x13, 0x04, 0x29, 0x10, 0x92, 0x40, 0x08, 0x04, 0x44, 0x82, 0x22, 0x00,
    0x19, 0x20, 0x00, 0x19, 0x20, 0x01, 0x81, 0x90, 0x60, 0x8a, 0x00, 0x41, 0xc0,
    0x02, 0x45, 0x10, 0x04, 0x00, 0x02, 0xa2, 0x09, 0x40, 0x10, 0x21, 0x49, 0x20,
    0x01, 0x42, 0x30, 0x2c, 0x00, 0x14, 0x44, 0x01, 0x22, 0x04, 0x02, 0x92, 0x08,
    0x89, 0x04, 0x21, 0x80, 0x10, 0x05, 0x01, 0x20, 0x40, 0x41, 0x80, 0x04, 0x00,
    0x12, 0x09, 0x40, 0xb0, 0x64, 0x58, 0x32, 0x01, 0x08, 0x90, 0x00, 0x41, 0x04,
    0x09, 0xc1, 0x80, 0x61, 0x08, 0x90, 0x00, 0x9a, 0x00, 0x24, 0x01, 0x12, 0x08,
    0x02, 0x26, 0x05, 0x82, 0x06, 0x08, 0x08, 0x00, 0x20, 0x48, 0x20, 0x00, 0x18,
    0x24, 0x48, 0x03, 0x02, 0x00, 0x11, 0x00, 0x09, 0x00, 0x84, 0x01, 0x4a, 0x10,
    0x01, 0x98, 0x00, 0x04, 0x18, 0x86, 0x00, 0xc0, 0x00, 0x20, 0x81, 0x80, 0x04,
    0x10, 0x30, 0x05, 0x00, 0xb4, 0x0c, 0x4a, 0x82, 0x29, 0x91, 0x02, 0x28, 0x00,
    0x20, 0x44, 0xc0, 0x00, 0x2c, 0x91, 0x80, 0x40, 0x01, 0xa2, 0x00, 0x12, 0x04,
    0x09, 0xc3, 0x20, 0x00, 0x08, 0x02, 0x0c, 0x10, 0x22, 0x04, 0x00, 0x00, 0x2c,
    0x11, 0x86, 0x00, 0xc0, 0x00, 0x00, 0x12, 0x32, 0x40, 0x89, 0x80, 0x40, 0x40,
    0x02, 0x05, 0x50, 0x86, 0x60, 0x82, 0xa4, 0x60, 0x0a, 0x12, 0x4d, 0x80, 0x90,
    0x08, 0x12, 0x80, 0x09, 0x02, 0x14, 0x48, 0x01, 0x24, 0x20, 0x8a, 0x00, 0x44,
    0x90, 0x04, 0x04, 0x01, 0x02, 0x00, 0xd1, 0x12, 0x00, 0x0a, 0x04, 0x40, 0x00,
    0x32, 0x21, 0x81, 0x24, 0x08, 0x19, 0x84, 0x20, 0x02, 0x04, 0x08, 0x89, 0x80,
    0x24, 0x02, 0x02, 0x68, 0x18, 0x82, 0x44, 0x42, 0x00, 0x21, 0x40, 0x00, 0x28,
    0x01, 0x80, 0x45, 0x82, 0x20, 0x40, 0x11, 0x80, 0x0c, 0x02, 0x00, 0x24, 0x40,
    0x90, 0x01, 0x40, 0x20, 0x20, 0x50, 0x20, 0x28, 0x19, 0x00, 0x40, 0x09, 0x20,
    0x08, 0x80, 0x04, 0x60, 0x40, 0x80, 0x20, 0x08, 0x30, 0x49, 0x09, 0x34, 0x00,
    0x11, 0x24, 0x24, 0x82, 0x00, 0x41, 0xc2, 0x00, 0x04, 0x92, 0x02, 0x24, 0x80,
    0x00, 0x0c, 0x02, 0xa0, 0x00, 0x01, 0x06, 0x60, 0x41, 0x04, 0x21, 0xd0, 0x00,
    0x01, 0x01, 0x00, 0x48, 0x12, 0x84, 0x04, 0x91, 0x12, 0x08, 0x00, 0x24, 0x44,
    0x00, 0x12, 0x41, 0x18, 0x26, 0x0c, 0x41, 0x80, 0x00, 0x52, 0x04, 0x20, 0x09,
    0x00, 0x24, 0x90, 0x20, 0x48, 0x18, 0x02, 0x00, 0x03, 0xa2, 0x09, 0xd0, 0x14,
    0x00, 0x8a, 0x84, 0x25, 0x4a, 0x00, 0x20, 0x98, 0x14, 0x40, 0x00, 0xa2, 0x05,
    0x00, 0x00, 0x00, 0x40, 0x14, 0x01, 0x58, 0x20, 0x2c, 0x80, 0x84, 0x00, 0x09,
    0x20, 0x20, 0x91, 0x02, 0x08, 0x02, 0xb0, 0x41, 0x08, 0x30, 0x00, 0x09, 0x10,
    0x00, 0x18, 0x02, 0x21, 0x02, 0x02, 0x00, 0x00, 0x24, 0x44, 0x08, 0x12, 0x60,
    0x00, 0xb2, 0x44, 0x12, 0x02, 0x0c, 0xc0, 0x80, 0x40, 0xc8, 0x20, 0x04, 0x50,
    0x20, 0x05, 0x00, 0xb0, 0x04, 0x0b, 0x04, 0x29, 0x53, 0x00, 0x61, 0x48, 0x30,
    0x00, 0x82, 0x20, 0x29, 0x00, 0x16, 0x00, 0x53, 0x22, 0x20, 0x43, 0x10, 0x48,
    0x00, 0x80, 0x04, 0xd2, 0x00, 0x40, 0x00, 0xa2, 0x44, 0x03, 0x80, 0x29, 0x00,
    0x04, 0x08, 0xc0, 0x04, 0x64, 0x40, 0x30, 0x28, 0x09, 0x84, 0x44, 0x50, 0x80,
    0x21, 0x02, 0x92, 0x00, 0xc0, 0x10, 0x60, 0x88, 0x22, 0x08, 0x80, 0x00, 0x00,
    0x18, 0x84, 0x04, 0x83, 0x96, 0x00, 0x81, 0x20, 0x05, 0x02, 0x00, 0x45, 0x88,
    0x84, 0x00, 0x51, 0x20, 0x20, 0x51, 0x86, 0x41, 0x4b, 0x94, 0x00, 0x80, 0x00,
    0x08, 0x11, 0x20, 0x4c, 0x58, 0x80, 0x04, 0x03, 0x06, 0x20, 0x89, 0x00, 0x05,
    0x08, 0x22, 0x05, 0x90, 0x00, 0x40, 0x00, 0x82, 0x09, 0x50, 0x00, 0x00, 0x00,
    0xa0, 0x41, 0xc2, 0x20, 0x08, 0x00, 0x16, 0x08, 0x40, 0x26, 0x21, 0xd0, 0x90,
    0x08, 0x81, 0x90, 0x41, 0x00, 0x02, 0x44, 0x08, 0x10, 0x0c, 0x0a, 0x86, 0x09,
    0x90, 0x04, 0x00, 0xc8, 0xa0, 0x04, 0x08, 0x30, 0x20, 0x89, 0x84, 0x00, 0x11,
    0x22, 0x2c, 0x40, 0x00, 0x08, 0x02, 0xb0, 0x01, 0x48, 0x02, 0x01, 0x09, 0x20,
    0x04, 0x03, 0x04, 0x00, 0x80, 0x02, 0x60, 0x42, 0x30, 0x21, 0x4a, 0x10, 0x44,
    0x09, 0x02, 0x00, 0x01, 0x24, 0x00, 0x12, 0x82, 0x21, 0x80, 0xa4, 0x20, 0x10,
    0x02, 0x04, 0x91, 0xa0, 0x40, 0x18, 0x04, 0x00, 0x02, 0x06, 0x69, 0x09, 0x00,
    0x05, 0x58, 0x02, 0x01, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x03, 0x92, 0x20,
    0x00, 0x34, 0x01, 0xc8, 0x20, 0x48, 0x08, 0x30, 0x08, 0x42, 0x80, 0x20, 0x91,
    0x90, 0x68, 0x01, 0x04, 0x40, 0x12, 0x02, 0x61, 0x00, 0x12, 0x08, 0x01, 0xa0,
    0x00, 0x11, 0x04, 0x21, 0x48, 0x04, 0x24, 0x92, 0x00, 0x0c, 0x01, 0x84, 0x04,
    0x00, 0x00, 0x01, 0x12, 0x96, 0x40, 0x01, 0xa0, 0x41, 0x88, 0x22, 0x28, 0x88,
    0x00, 0x44, 0x42, 0x80, 0x24, 0x12, 0x14, 0x01, 0x42, 0x90, 0x60, 0x1a, 0x10,
    0x04, 0x81, 0x10, 0x48, 0x08, 0x06, 0x29, 0x83, 0x02, 0x40, 0x02, 0x24, 0x64,
    0x80, 0x10, 0x05, 0x80, 0x10, 0x40, 0x02, 0x02, 0x08, 0x42, 0x84, 0x01, 0x09,
    0x20, 0x04, 0x50, 0x00, 0x60, 0x11, 0x30, 0x40, 0x13, 0x02, 0x04, 0x81, 0x00,
    0x09, 0x08, 0x20, 0x45, 0x4a, 0x10, 0x61, 0x90, 0x26, 0x0c, 0x08, 0x02, 0x21,
    0x91, 0x00, 0x60, 0x02, 0x04, 0x00, 0x02, 0x00, 0x0c, 0x08, 0x06, 0x08, 0x48,
    0x84, 0x08, 0x11, 0x02, 0x00, 0x80, 0xa4, 0x00, 0x5a, 0x20, 0x00, 0x88, 0x04,
    0x04, 0x02, 0x00, 0x09, 0x00, 0x14, 0x08, 0x49, 0x14, 0x20, 0xc8, 0x00, 0x04,
    0x91, 0xa0, 0x40, 0x59, 0x80, 0x00, 0x12, 0x10, 0x00, 0x80, 0x80, 0x65, 0x00,
    0x00, 0x04, 0x00, 0x80, 0x40, 0x19, 0x00, 0x21, 0x03, 0x84, 0x60, 0xc0, 0x04,
    0x24, 0x1a, 0x12, 0x61, 0x80, 0x80, 0x08, 0x02, 0x04, 0x09, 0x42, 0x12, 0x20,
    0x08, 0x34, 0x04, 0x90, 0x20, 0x01, 0x01, 0xa0, 0x00, 0x0b, 0x00, 0x08, 0x91,
    0x92, 0x40, 0x02, 0x34, 0x40, 0x88, 0x10, 0x61, 0x19, 0x02, 0x00, 0x40, 0x04,
    0x25, 0xc0, 0x80, 0x68, 0x08, 0x04, 0x21, 0x80, 0x22, 0x04, 0x00, 0xa0, 0x0c,
    0x01, 0x84, 0x20, 0x41, 0x00, 0x08, 0x8a, 0x00, 0x20, 0x8a, 0x00, 0x48, 0x88,
    0x04, 0x04, 0x11, 0x82, 0x08, 0x40, 0x86, 0x09, 0x49, 0xa4, 0x40, 0x00, 0x10,
    0x01, 0x01, 0xa2, 0x04, 0x50, 0x80, 0x0c, 0x80, 0x00, 0x48, 0x82, 0xa0, 0x01,
    0x18, 0x12, 0x41, 0x01, 0x04, 0x48, 0x41, 0x00, 0x24, 0x01, 0x00, 0x00, 0x88,
    0x14, 0x00, 0x02, 0x00, 0x68, 0x01, 0x20, 0x08, 0x4a, 0x22, 0x08, 0x83, 0x80,
    0x00, 0x89, 0x04, 0x01, 0xc2, 0x00, 0x00, 0x00, 0x34, 0x04, 0x00, 0x82, 0x28,
    0x02, 0x02, 0x41, 0x4a, 0x90, 0x05, 0x82, 0x02, 0x09, 0x80, 0x24, 0x04, 0x41,
    0x00, 0x01, 0x92, 0x80, 0x28, 0x01, 0x14, 0x00, 0x50, 0x20, 0x4c, 0x10, 0xb0,
    0x04, 0x43, 0xa4, 0x21, 0x90, 0x04, 0x01, 0x02, 0x00, 0x44, 0x48, 0x00, 0x64,
    0x08, 0x06, 0x00, 0x42, 0x20, 0x08, 0x02, 0x92, 0x01, 0x4a, 0x00, 0x20, 0x50,
    0x32, 0x25, 0x90, 0x22, 0x04, 0x09, 0x00, 0x08, 0x11, 0x80, 0x21, 0x01, 0x10,
    0x05, 0x00, 0x32, 0x08, 0x88, 0x94, 0x08, 0x08, 0x24, 0x0d, 0xc1, 0x80, 0x40,
    0x0b, 0x20, 0x40, 0x18, 0x12, 0x04, 0x00, 0x22, 0x40, 0x10, 0x26, 0x05, 0xc1,
    0x82, 0x00, 0x01, 0x30, 0x24, 0x02, 0x22, 0x41, 0x08, 0x24, 0x48, 0x1a, 0x00,
    0x25, 0xd2, 0x12, 0x28, 0x42, 0x00, 0x04, 0x40, 0x30, 0x41, 0x00, 0x02, 0x00,
    0x13, 0x20, 0x24, 0xd1, 0x84, 0x08, 0x89, 0x80, 0x04, 0x52, 0x00, 0x44, 0x18,
    0xa4, 0x00, 0x00, 0x06, 0x20, 0x91, 0x10, 0x09, 0x42, 0x20, 0x24, 0x40, 0x30,
    0x28, 0x00, 0x84, 0x40, 0x40, 0x80, 0x08, 0x10, 0x04, 0x09, 0x08, 0x04, 0x40,
    0x08, 0x22, 0x00, 0x19, 0x02, 0x00, 0x00, 0x80, 0x2c, 0x02, 0x02, 0x21, 0x01,
    0x90, 0x20, 0x40, 0x00, 0x0c, 0x00, 0x34, 0x48, 0x58, 0x20, 0x01, 0x43, 0x04,
    0x20, 0x80, 0x14, 0x00, 0x90, 0x00, 0x6d, 0x11, 0x00, 0x00, 0x40, 0x20, 0x00,
    0x03, 0x10, 0x40, 0x88, 0x30, 0x05, 0x4a, 0x00, 0x65, 0x10, 0x24, 0x08, 0x18,
    0x84, 0x28, 0x03, 0x80, 0x20, 0x42, 0xb0, 0x40, 0x00, 0x10, 0x69, 0x19, 0x04,
    0x00, 0x00, 0x80, 0x04, 0xc2, 0x04, 0x00, 0x01, 0x00, 0x05, 0x00, 0x22, 0x25,
    0x08, 0x96, 0x04, 0x02, 0x22, 0x00, 0xd0, 0x10, 0x29, 0x01, 0xa0, 0x60, 0x08,
    0x10, 0x04, 0x01, 0x16, 0x44, 0x10, 0x02, 0x28, 0x02, 0x82, 0x48, 0x40, 0x84,
    0x20, 0x90, 0x22, 0x28, 0x80, 0x04, 0x00, 0x40, 0x04, 0x24, 0x00, 0x80, 0x29,
    0x03, 0x10, 0x60, 0x48, 0x00, 0x00, 0x81, 0xa0, 0x00, 0x51, 0x20, 0x0c, 0xd1,
    0x00, 0x01, 0x41, 0x20, 0x04, 0x92, 0x00, 0x00, 0x10, 0x92, 0x00, 0x42, 0x04,
    0x05, 0x01, 0x86, 0x40, 0x80, 0x10, 0x20, 0x52, 0x20, 0x21, 0x00, 0x10, 0x48,
    0x0a, 0x02, 0x00, 0xd0, 0x12, 0x41, 0x48, 0x80, 0x04, 0x00, 0x00, 0x48, 0x09,
    0x22, 0x04, 0x00, 0x24, 0x00, 0x43, 0x10, 0x60, 0x0a, 0x00, 0x44, 0x12, 0x20,
    0x2c, 0x08, 0x20, 0x44, 0x00, 0x84, 0x09, 0x40, 0x06, 0x08, 0xc1, 0x00, 0x40,
    0x80, 0x20, 0x00, 0x98, 0x12, 0x48, 0x10, 0xa2, 0x20, 0x00, 0x84, 0x48, 0xc0,
    0x10, 0x20, 0x90, 0x12, 0x08, 0x98, 0x82, 0x00, 0x0a, 0xa0, 0x04, 0x03, 0x00,
    0x28, 0xc3, 0x00, 0x44, 0x42, 0x10, 0x04, 0x08, 0x04, 0x40, 0x00, 0x00, 0x05,
    0x10, 0x00, 0x21, 0x03, 0x80, 0x04, 0x88, 0x12, 0x69, 0x10, 0x00, 0x04, 0x08,
    0x04, 0x04, 0x02, 0x84, 0x48, 0x49, 0x04, 0x20, 0x18, 0x02, 0x64, 0x80, 0x30,
    0x08, 0x01, 0x02, 0x00, 0x52, 0x12, 0x49, 0x08, 0x20, 0x41, 0x88, 0x10, 0x48,
    0x08, 0x34, 0x00, 0x01, 0x86, 0x05, 0xd0, 0x00, 0x00, 0x83, 0x84, 0x21, 0x40,
    0x02, 0x41, 0x10, 0x80, 0x48, 0x40, 0xa2, 0x20, 0x51, 0x00, 0x00, 0x49, 0x00,
    0x01, 0x90, 0x20, 0x40, 0x18, 0x02, 0x40, 0x02, 0x22, 0x05, 0x40, 0x80, 0x08,
    0x82, 0x10, 0x20, 0x18, 0x00, 0x05, 0x01, 0x82, 0x40, 0x58, 0x00, 0x04, 0x81,
    0x90, 0x29, 0x01, 0xa0, 0x64, 0x00, 0x22, 0x40, 0x01, 0xa2, 0x00, 0x18, 0x04,
    0x0d, 0x00, 0x00, 0x60, 0x80, 0x94, 0x60, 0x82, 0x10, 0x0d, 0x80, 0x30, 0x0c,
    0x12, 0x20, 0x00, 0x00, 0x12, 0x40, 0xc0, 0x20, 0x21, 0x58, 0x02, 0x41, 0x10,
    0x80, 0x44, 0x03, 0x02, 0x04, 0x13, 0x90, 0x29, 0x08, 0x00, 0x44, 0xc0, 0x00,
    0x21, 0x00, 0x26, 0x00, 0x1a, 0x80, 0x01, 0x13, 0x14, 0x20, 0x0a, 0x14, 0x20,
    0x00, 0x32, 0x61, 0x08, 0x00, 0x40, 0x42, 0x20, 0x09, 0x80, 0x06, 0x01, 0x81,
    0x80, 0x60, 0x42, 0x00, 0x68, 0x90, 0x82, 0x08, 0x42, 0x80, 0x04, 0x02, 0x80,
    0x09, 0x0b, 0x04, 0x00, 0x98, 0x00, 0x0c, 0x81, 0x06, 0x44, 0x48, 0x84, 0x28,
    0x03, 0x92, 0x00, 0x01, 0x80, 0x40, 0x0a, 0x00, 0x0c, 0x81, 0x02, 0x08, 0x51,
    0x04, 0x28, 0x90, 0x02, 0x20, 0x09, 0x10, 0x60, 0x00, 0x00, 0x09, 0x81, 0xa0,
    0x0c, 0x00, 0xa4, 0x09, 0x00, 0x02, 0x28, 0x80, 0x20, 0x00, 0x02, 0x02, 0x04,
    0x81, 0x14, 0x04, 0x00, 0x04, 0x09, 0x11, 0x12, 0x60, 0x40, 0x20, 0x01, 0x48,
    0x30, 0x40, 0x11, 0x00, 0x08, 0x0a, 0x86, 0x00, 0x00, 0x04, 0x60, 0x81, 0x04,
    0x01, 0xd0, 0x02, 0x41, 0x18, 0x90, 0x00, 0x0a, 0x20, 0x00, 0xc1, 0x06, 0x01,
    0x08, 0x80, 0x64, 0xca, 0x10, 0x04, 0x99, 0x80, 0x48, 0x01, 0x82, 0x20, 0x50,
    0x90, 0x48, 0x80, 0x84, 0x20, 0x90, 0x22, 0x00, 0x19, 0x00, 0x04, 0x18, 0x20,
    0x24, 0x10, 0x86, 0x40, 0xc2, 0x00, 0x24, 0x12, 0x10, 0x44, 0x00, 0x16, 0x08,
    0x10, 0x24, 0x00, 0x12, 0x06, 0x01, 0x08, 0x90, 0x00, 0x12, 0x02, 0x4d, 0x10,
    0x80, 0x40, 0x50, 0x22, 0x00, 0x43, 0x10, 0x01, 0x00, 0x30, 0x21, 0x0a, 0x00,
    0x00, 0x01, 0x14, 0x00, 0x10, 0x84, 0x04, 0xc1, 0x10, 0x29, 0x0a, 0x00, 0x01,
    0x8a, 0x00, 0x20, 0x01, 0x12, 0x0c, 0x49, 0x20, 0x04, 0x81, 0x00, 0x48, 0x01,
    0x04, 0x60, 0x80, 0x12, 0x0c, 0x08, 0x10, 0x48, 0x4a, 0x04, 0x28, 0x10, 0x00,
    0x28, 0x40, 0x84, 0x45, 0x50, 0x10, 0x60, 0x10, 0x06, 0x44, 0x01, 0x80, 0x09,
    0x00, 0x86, 0x01, 0x42, 0xa0, 0x00, 0x90, 0x00, 0x05, 0x90, 0x22, 0x40, 0x41,
    0x00, 0x08, 0x80, 0x02, 0x08, 0xc0, 0x00, 0x01, 0x58, 0x30, 0x49, 0x09, 0x14,
    0x00, 0x41, 0x02, 0x0c, 0x02, 0x80, 0x40, 0x89, 0x00, 0x24, 0x08, 0x10, 0x05,
    0x90, 0x32, 0x40, 0x0a, 0x82, 0x08, 0x00, 0x12, 0x61, 0x00, 0x04, 0x21, 0x00,
    0x22, 0x04, 0x10, 0x24, 0x08, 0x0a, 0x04, 0x01, 0x10, 0x00, 0x20, 0x40, 0x84,
    0x04, 0x88, 0x22, 0x20, 0x90, 0x12, 0x00, 0x53, 0x06, 0x24, 0x01, 0x04, 0x40,
    0x0b, 0x14, 0x60, 0x82, 0x02, 0x0d, 0x10, 0x90, 0x0c, 0x08, 0x20, 0x09, 0x00,
    0x14, 0x09, 0x80, 0x80, 0x24, 0x82, 0x00, 0x40, 0x01, 0x02, 0x44, 0x01, 0x20,
    0x0c, 0x40, 0x84, 0x40, 0x0a, 0x10, 0x41, 0x00, 0x30, 0x05, 0x09, 0x80, 0x44,
    0x08, 0x20, 0x20, 0x02, 0x00, 0x49, 0x43, 0x20, 0x21, 0x00, 0x20, 0x00, 0x01,
    0xb6, 0x08, 0x40, 0x04, 0x08, 0x02, 0x80, 0x01, 0x41, 0x80, 0x40, 0x08, 0x10,
    0x24, 0x00, 0x20, 0x04, 0x12, 0x86, 0x09, 0xc0, 0x12, 0x21, 0x81, 0x14, 0x04,
    0x00, 0x02, 0x20, 0x89, 0xb4, 0x44, 0x12, 0x80, 0x00, 0xd1, 0x00, 0x69, 0x40,
    0x80, 0x00, 0x42, 0x12, 0x00, 0x18, 0x04, 0x00, 0x49, 0x06, 0x21, 0x02, 0x04,
    0x28, 0x02, 0x84, 0x01, 0xc0, 0x10, 0x68, 0x00, 0x20, 0x08, 0x40, 0x00, 0x08,
    0x91, 0x10, 0x01, 0x81, 0x24, 0x04, 0xd2, 0x10, 0x4c, 0x88, 0x86, 0x00, 0x10,
    0x80, 0x0c, 0x02, 0x14, 0x00, 0x8a, 0x90, 0x40, 0x18, 0x20, 0x21, 0x80, 0xa4,
    0x00, 0x58, 0x24, 0x20, 0x10, 0x10, 0x60, 0xc1, 0x30, 0x41, 0x48, 0x02, 0x48,
    0x09, 0x00, 0x40, 0x09, 0x02, 0x05, 0x11, 0x82, 0x20, 0x4a, 0x20, 0x24, 0x18,
    0x02, 0x0c, 0x10, 0x22, 0x0c, 0x0a, 0x04, 0x00, 0x03, 0x06, 0x48, 0x48, 0x04,
    0x04, 0x02, 0x00, 0x21, 0x80, 0x84, 0x00, 0x18, 0x00, 0x0c, 0x02, 0x12, 0x01,
    0x00, 0x14, 0x05, 0x82, 0x10, 0x41, 0x89, 0x12, 0x08, 0x40, 0xa4, 0x21, 0x01,
    0x84, 0x48, 0x02, 0x10, 0x60, 0x40, 0x02, 0x28, 0x00, 0x14, 0x08, 0x40, 0xa0,
    0x20, 0x51, 0x12, 0x00, 0xc2, 0x00, 0x01, 0x1a, 0x30, 0x40, 0x89, 0x12, 0x4c,
    0x02, 0x80, 0x00, 0x00, 0x14, 0x01, 0x01, 0xa0, 0x21, 0x18, 0x22, 0x21, 0x18,
    0x06, 0x40, 0x01, 0x80, 0x00, 0x90, 0x04, 0x48, 0x02, 0x30, 0x04, 0x08, 0x00,
    0x05, 0x88, 0x24, 0x08, 0x48, 0x04, 0x24, 0x02, 0x06, 0x00, 0x80, 0x00, 0x00,
    0x00, 0x10, 0x65, 0x11, 0x90, 0x00, 0x0a, 0x82, 0x04, 0xc3, 0x04, 0x60, 0x48,
    0x24, 0x04, 0x92, 0x02, 0x44, 0x88, 0x80, 0x40, 0x18, 0x06, 0x29, 0x80, 0x10,
    0x01, 0x00, 0x00, 0x44, 0xc8, 0x10, 0x21, 0x89, 0x30, 0x00, 0x4b, 0xa0, 0x01,
    0x10, 0x14, 0x00, 0x02, 0x94, 0x40, 0x00, 0x20, 0x65, 0x00, 0xa2, 0x0c, 0x40,
    0x22, 0x20, 0x81, 0x12, 0x20, 0x82, 0x04, 0x01, 0x10, 0x00, 0x08, 0x88, 0x00,
    0x00, 0x11, 0x80, 0x04, 0x42, 0x80, 0x40, 0x41, 0x14, 0x00, 0x40, 0x32, 0x2c,
    0x80, 0x24, 0x04, 0x19, 0x00, 0x00, 0x91, 0x00, 0x20, 0x83, 0x00, 0x05, 0x40,
    0x20, 0x09, 0x01, 0x84, 0x40, 0x40, 0x20, 0x20, 0x11, 0x00, 0x40, 0x41, 0x90,
    0x20, 0x00, 0x00, 0x40, 0x90, 0x92, 0x48, 0x18, 0x06, 0x08, 0x81, 0x80, 0x48,
    0x01, 0x34, 0x24, 0x10, 0x20, 0x04, 0x00, 0x20, 0x04, 0x18, 0x06, 0x2d, 0x90,
    0x10, 0x01, 0x00, 0x90, 0x00, 0x0a, 0x22, 0x01, 0x00, 0x22, 0x00, 0x11, 0x84,
    0x01, 0x01, 0x00, 0x20, 0x88, 0x00, 0x44, 0x00, 0x22, 0x01, 0x00, 0xa6, 0x40,
    0x02, 0x06, 0x20, 0x11, 0x00, 0x01, 0xc8, 0xa0, 0x04, 0x8a, 0x00, 0x28, 0x19,
    0x80, 0x00, 0x52, 0xa0, 0x24, 0x12, 0x12, 0x09, 0x08, 0x24, 0x01, 0x48, 0x00,
    0x04, 0x00, 0x24, 0x40, 0x02, 0x84, 0x08, 0x00, 0x04, 0x48, 0x40, 0x90, 0x60,
    0x0a, 0x22, 0x01, 0x88, 0x14, 0x08, 0x01, 0x02, 0x08, 0xd3, 0x00, 0x20, 0xc0,
    0x90, 0x24, 0x10, 0x00, 0x00, 0x01, 0xb0, 0x08, 0x0a, 0xa0, 0x00, 0x80, 0x00,
    0x01, 0x09, 0x00, 0x20, 0x52, 0x02, 0x25, 0x00, 0x24, 0x04, 0x02, 0x84, 0x24,
    0x10, 0x92, 0x40, 0x02, 0xa0, 0x40, 0x00, 0x22, 0x08, 0x11, 0x04, 0x08, 0x01,
    0x22, 0x00, 0x42, 0x14, 0x00, 0x09, 0x90, 0x21, 0x00, 0x30, 0x6c, 0x00, 0x00,
    0x0c, 0x00, 0x22, 0x09, 0x90, 0x10, 0x28, 0x40, 0x00, 0x20, 0xc0, 0x20, 0x00,
    0x90, 0x00, 0x40, 0x01, 0x82, 0x05, 0x12, 0x12, 0x09, 0xc1, 0x04, 0x61, 0x80,
    0x02, 0x28, 0x81, 0x24, 0x00, 0x49, 0x04, 0x08, 0x10, 0x86, 0x29, 0x41, 0x80,
    0x21, 0x0a, 0x30, 0x49, 0x88, 0x90, 0x00, 0x41, 0x04, 0x29, 0x81, 0x80, 0x41,
    0x09, 0x00, 0x40, 0x12, 0x10, 0x40, 0x00, 0x10, 0x40, 0x48, 0x02, 0x05, 0x80,
    0x02, 0x21, 0x40, 0x20, 0x00, 0x58, 0x20, 0x60, 0x00, 0x90, 0x48, 0x00, 0x80,
    0x28, 0xc0, 0x80, 0x48, 0x00, 0x00, 0x44, 0x80, 0x02, 0x00, 0x09, 0x06, 0x00,
    0x12, 0x02, 0x01, 0x00, 0x10, 0x08, 0x83, 0x10, 0x45, 0x12, 0x00, 0x2c, 0x08,
    0x04, 0x44, 0x00, 0x20, 0x20, 0xc0, 0x10, 0x20, 0x01, 0x00, 0x05, 0xc8, 0x20,
    0x04, 0x98, 0x10, 0x08, 0x10, 0x00, 0x24, 0x02, 0x16, 0x40, 0x88, 0x00, 0x61,
    0x88, 0x12, 0x24, 0x80, 0xa6, 0x00, 0x42, 0x00, 0x08, 0x10, 0x06, 0x48, 0x40,
    0xa0, 0x00, 0x50, 0x20, 0x04, 0x81, 0xa4, 0x40, 0x18, 0x00, 0x08, 0x10, 0x80,
    0x01, 0x01
)
