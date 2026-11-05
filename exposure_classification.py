#!/usr/bin/env python3
"""BIP 362 reference implementation; Python 3.7+, standard library only.

SPDX-License-Identifier: BSD-2-Clause OR CC0-1.0
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, replace
from enum import Enum
from pathlib import Path
from typing import Optional


class Level(str, Enum):
    EXPOSED_AT_REST = "EXPOSED_AT_REST"
    EXPOSED_ON_SPEND = "EXPOSED_ON_SPEND"
    NOT_EXPOSED = "NOT_EXPOSED"
    UNDETERMINED = "UNDETERMINED"


ACTION = {
    Level.EXPOSED_AT_REST: "MIGRATE",
    Level.EXPOSED_ON_SPEND: "SWEEP_WHEN_SPENDING",
    Level.NOT_EXPOSED: "NONE",
    Level.UNDETERMINED: "MIGRATE",
}


def recommended_action(level: Level) -> str:
    return ACTION[level]


_RL = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
    4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
]
_RR = [
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
    6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
    8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
    12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
]
_SL = [
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
    7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
    11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
    9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
]
_SR = [
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
    9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
    9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
    15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
    8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
]
_KL = [0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E]
_KR = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000]
_M32 = 0xFFFFFFFF


def _rmd_f(j: int, x: int, y: int, z: int) -> int:
    if j == 0:
        return x ^ y ^ z
    if j == 1:
        return (x & y) | (~x & z)
    if j == 2:
        return (x | ~y) ^ z
    if j == 3:
        return (x & z) | (y & ~z)
    return x ^ (y | ~z)


def _rol(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & _M32


def ripemd160_py(data: bytes) -> bytes:
    """Pure-Python RIPEMD-160, for builds whose OpenSSL lacks it."""
    msg = bytes(data) + b"\x80"
    msg += b"\x00" * ((56 - len(msg)) % 64) + (8 * len(data)).to_bytes(8, "little")
    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    for off in range(0, len(msg), 64):
        x = [int.from_bytes(msg[off + 4 * i : off + 4 * i + 4], "little") for i in range(16)]
        al, bl, cl, dl, el = h
        ar, br, cr, dr, er = h
        for j in range(80):
            r = j // 16
            t = _rol((al + _rmd_f(r, bl, cl, dl) + x[_RL[j]] + _KL[r]) & _M32, _SL[j])
            al, bl, cl, dl, el = el, (t + el) & _M32, bl, _rol(cl, 10), dl
            t = _rol((ar + _rmd_f(4 - r, br, cr, dr) + x[_RR[j]] + _KR[r]) & _M32, _SR[j])
            ar, br, cr, dr, er = er, (t + er) & _M32, br, _rol(cr, 10), dr
        h = [
            (h[1] + cl + dr) & _M32,
            (h[2] + dl + er) & _M32,
            (h[3] + el + ar) & _M32,
            (h[4] + al + br) & _M32,
            (h[0] + bl + cr) & _M32,
        ]
    return b"".join(v.to_bytes(4, "little") for v in h)


def _hashlib_ripemd160() -> bool:
    try:
        hashlib.new("ripemd160")
    except ValueError:
        return False
    return True


#: Some OpenSSL 3 builds drop RIPEMD-160 from hashlib; fall back to ours then.
HAVE_HASHLIB_RIPEMD160 = _hashlib_ripemd160()


def ripemd160(data: bytes) -> bytes:
    if HAVE_HASHLIB_RIPEMD160:
        return hashlib.new("ripemd160", data).digest()
    return ripemd160_py(data)


def hash160(data: bytes) -> bytes:
    """RIPEMD-160 of SHA-256, as committed to by P2PKH and P2WPKH."""
    return ripemd160(hashlib.sha256(data).digest())



_P = 2**256 - 2**32 - 977


def _lift_x(x):
    if not 0 <= x < _P:
        return None
    y2 = (pow(x, 3, _P) + 7) % _P
    y = pow(y2, (_P + 1) // 4, _P)
    if y * y % _P != y2:
        return None
    return y if y % 2 == 0 else _P - y


def key_x(key: bytes) -> Optional[bytes]:
    """Validate an SEC or BIP 340 encoding and return its x-coordinate."""
    if len(key) == 32:
        return key if _lift_x(int.from_bytes(key, 'big')) is not None else None
    if len(key) not in (33, 65):
        return None
    x = key[1:33]
    if _lift_x(int.from_bytes(x, 'big')) is None:
        return None
    if len(key) == 33:
        return x if key[0] in (2, 3) else None
    if key[0] not in (4, 6, 7):
        return None
    y = int.from_bytes(key[33:], 'big')
    if y >= _P or (y * y - pow(int.from_bytes(x, 'big'), 3, _P) - 7) % _P:
        return None
    if key[0] in (6, 7) and key[0] != 6 + y % 2:
        return None
    return x


def key_encodings(x: bytes):
    """Return all six SEC encodings of the points with this x-coordinate."""
    y = _lift_x(int.from_bytes(x, 'big'))
    if len(x) != 32 or y is None:
        raise ValueError('invalid x-coordinate')
    even = y.to_bytes(32, 'big')
    odd = (_P - y).to_bytes(32, 'big')
    return (b'\x02' + x, b'\x03' + x,
            b'\x04' + x + even, b'\x04' + x + odd,
            b'\x06' + x + even, b'\x07' + x + odd)


def instructions(script):
    """Yield (opcode, pushed bytes or None), stopping at an incomplete push."""
    pos = 0
    while pos < len(script):
        op = script[pos]
        pos += 1
        if op <= 78:
            size = op
            if op >= 76:
                width = {76: 1, 77: 2, 78: 4}[op]
                if pos + width > len(script):
                    return
                size = int.from_bytes(script[pos:pos + width], 'little')
                pos += width
            if pos + size > len(script):
                return
            yield op, script[pos:pos + size]
            pos += size
        else:
            yield op, None


def _small_int(op):
    if op == 0:
        return 0
    if 81 <= op <= 96:
        return op - 80
    return None


def _witness_program(script):
    if 4 <= len(script) <= 42:
        version = _small_int(script[0])
        if version is not None and script[1] == len(script) - 2:
            return version, script[2:]
    return None


@dataclass(frozen=True)
class ScriptType:
    name: str
    commitment: bytes = b''
    keys: tuple = ()
    required: int = 0


def recognize(script: bytes, bip360_active=False) -> ScriptType:
    if script.startswith(b'\x6a'):
        return ScriptType('unclassified')
    wp = _witness_program(script)
    if wp is not None:
        version, program = wp
        if version == 0:
            return ScriptType({20: 'P2WPKH', 32: 'P2WSH'}.get(len(program),
                              'unclassified'), program)
        if version == 1 and len(program) == 32:
            return ScriptType('P2TR', keys=(program,), required=1)
        if version == 2 and len(program) == 32 and bip360_active:
            return ScriptType('P2MR', program)
        return ScriptType('unknown')
    if len(script) == 25 and script[:3] == b'\x76\xa9\x14' and script[-2:] == b'\x88\xac':
        return ScriptType('P2PKH', script[3:23])
    if len(script) == 23 and script[:2] == b'\xa9\x14' and script[-1:] == b'\x87':
        return ScriptType('P2SH', script[2:22])
    # Requiring a decoded final opcode excludes truncated trailing pushes.
    ops = list(instructions(script))
    decoded_size = sum(1 + (0 if data is None else len(data)) +
                       ({76: 1, 77: 2, 78: 4}.get(op, 0)) for op, data in ops)
    if decoded_size != len(script):
        return ScriptType('unknown')
    if script.endswith(b'\xac') and len(ops) == 2 and ops[-1] == (172, None):
        key = ops[0][1]
        if key is not None and len(key) in (33, 65):
            return ScriptType('P2PK', keys=(key,), required=1)
    if script.endswith(b'\xae') and len(ops) >= 3 and ops[-1] == (174, None):
        m, n = _small_int(ops[0][0]), _small_int(ops[-2][0])
        keys = tuple(data for _, data in ops[1:-2])
        if (m is not None and n is not None and m <= n and n == len(keys)
                and all(k is not None and len(k) in (33, 65) for k in keys)):
            return ScriptType('multisig', keys=keys, required=m)
    return ScriptType('unknown')


def _compact_size(n):
    if n < 253:
        return bytes([n])
    for prefix, width in ((253, 2), (254, 4), (255, 8)):
        if n < 1 << (width * 8):
            return bytes([prefix]) + n.to_bytes(width, 'little')
    raise ValueError('CompactSize overflow')


def _tagged_hash(tag, data):
    tag_hash = hashlib.sha256(tag).digest()
    return hashlib.sha256(tag_hash + tag_hash + data).digest()


@dataclass(frozen=True)
class RevealedLeaf:
    version: int
    script: bytes
    path: tuple = ()

    def __post_init__(self):
        if not 0 <= self.version <= 254 or self.version & 1:
            raise ValueError('invalid leaf version')
        if any(len(h) != 32 for h in self.path):
            raise ValueError('invalid Merkle path hash')
        object.__setattr__(self, 'path', tuple(self.path))


def leaf_hashes(leaf):
    """Return k_0 through k_m; sibling hashes are deliberately excluded."""
    h = _tagged_hash(b'TapLeaf', bytes([leaf.version]) +
                     _compact_size(len(leaf.script)) + leaf.script)
    result = [h]
    for sibling in leaf.path:
        h = _tagged_hash(b'TapBranch', min(h, sibling) + max(h, sibling))
        result.append(h)
    return tuple(result)


@dataclass(frozen=True)
class ChainEvidence:
    """Evidence from confirmed transactions up to one evaluated block.

    Match sets are snapshots computed once. Construct a new object to add evidence.
    A positive own_spend_count must count spends under the output type's rules.
    """
    published_keys: tuple = ()
    revealed_scripts: tuple = ()
    revealed_leaves: tuple = ()
    own_spend_count: Optional[int] = None
    complete: bool = False
    bip360_active: bool = False
    p2sh_matches: frozenset = field(init=False, repr=False)
    p2wsh_matches: frozenset = field(init=False, repr=False)
    p2mr_matches: frozenset = field(init=False, repr=False)
    key_hashes: frozenset = field(init=False, repr=False)
    wrapped_key_hashes: frozenset = field(init=False, repr=False)

    def __post_init__(self):
        if self.own_spend_count is not None and self.own_spend_count < 0:
            raise ValueError('negative own-spend count')
        xs = frozenset(x for x in (key_x(k) for k in self.published_keys) if x is not None)
        scripts = frozenset(self.revealed_scripts)
        leaves = tuple(self.revealed_leaves)
        all_scripts = scripts | frozenset(leaf.script for leaf in leaves)
        sh, wsh, mr, kh, wrapped = set(), set(), set(), set(), set()
        for script in all_scripts:
            digest = hashlib.sha256(script).digest()
            sh.update((hash160(script), hash160(b'\x00\x20' + digest)))
            wsh.add(digest)
        for leaf in leaves:
            mr.update(leaf_hashes(leaf))
        for x in xs:
            for encoding in key_encodings(x):
                digest = hash160(encoding)
                kh.add(digest)
                wrapped.add(hash160(b'\x00\x14' + digest))
        for name, value in (('published_keys', xs), ('revealed_scripts', scripts),
                            ('revealed_leaves', leaves), ('p2sh_matches', frozenset(sh)),
                            ('p2wsh_matches', frozenset(wsh)), ('p2mr_matches', frozenset(mr)),
                            ('key_hashes', frozenset(kh)),
                            ('wrapped_key_hashes', frozenset(wrapped))):
            object.__setattr__(self, name, value)


def classify(script: bytes, evidence: Optional[ChainEvidence] = None) -> Optional[Level]:
    evidence = evidence if evidence is not None else ChainEvidence()
    t = recognize(script, evidence.bip360_active)
    if t.name == 'unclassified':
        return None
    if t.name in ('P2PK', 'multisig', 'P2TR'):
        valid = sum(key_x(k) is not None for k in t.keys)
        return Level.EXPOSED_AT_REST if valid >= t.required else Level.UNDETERMINED
    if t.name == 'unknown':
        return Level.UNDETERMINED
    script_matches = {'P2SH': evidence.p2sh_matches,
                      'P2WSH': evidence.p2wsh_matches, 'P2MR': evidence.p2mr_matches}
    if t.commitment in script_matches.get(t.name, ()):
        return Level.EXPOSED_AT_REST
    if t.name in ('P2PKH', 'P2WPKH') and t.commitment in evidence.key_hashes:
        return Level.EXPOSED_AT_REST
    if t.name == 'P2SH' and t.commitment in evidence.wrapped_key_hashes:
        return Level.EXPOSED_AT_REST
    if evidence.own_spend_count is not None and evidence.own_spend_count > 0:
        return Level.EXPOSED_AT_REST
    return Level.EXPOSED_ON_SPEND if evidence.complete else Level.UNDETERMINED


class _Reader:
    def __init__(self, data):
        self.data, self.pos = data, 0

    def take(self, size):
        if size > len(self.data) - self.pos:
            raise ValueError('truncated transaction')
        result = self.data[self.pos:self.pos + size]
        self.pos += size
        return result

    def count(self):
        first = self.take(1)[0]
        if first < 253:
            return first
        width = {253: 2, 254: 4, 255: 8}[first]
        value = int.from_bytes(self.take(width), 'little')
        if value < {253: 253, 254: 65536, 255: 4294967296}[first]:
            raise ValueError('non-canonical CompactSize')
        return value

    def vector(self):
        return self.take(self.count())


def _parse_transaction(tx):
    r = _Reader(tx)
    r.take(4)
    segwit = tx[4:5] == b'\x00'
    if segwit and r.take(2) != b'\x00\x01':
        raise ValueError('invalid witness marker or flags')
    inputs = []
    for _ in range(r.count()):
        prev = r.take(36)
        script = r.vector()
        r.take(4)
        inputs.append((prev == b'\x00' * 32 + b'\xff' * 4, script))
    outputs = []
    for _ in range(r.count()):
        r.take(8)
        outputs.append(r.vector())
    witnesses = [() for _ in inputs]
    if segwit:
        witnesses = [tuple(r.vector() for _ in range(r.count())) for _ in inputs]
        if not any(witnesses):
            raise ValueError('superfluous witness serialization')
    r.take(4)
    if r.pos != len(tx):
        raise ValueError('trailing transaction bytes')
    return inputs, outputs, witnesses


def extract_evidence(tx: bytes, prevout_scripts, bip360_active=False, *,
                     taproot_active=True, bip16_active=True) -> ChainEvidence:
    """Extract partial evidence, without verifying signatures or commitments.

    prevout_scripts has one bytes entry per input; a coinbase entry may be None.
    The caller supplies only confirmed transactions and their activation states.
    P2SH extraction requires bip16_active in the spending block.
    P2TR/P2MR script-path extraction requires taproot_active/bip360_active,
    respectively. General SEC key scanning still applies to every input.
    Raises ValueError on malformed transaction serialization.
    """
    inputs, outputs, witnesses = _parse_transaction(tx)
    if len(prevout_scripts) != len(inputs):
        raise ValueError('one prevout script is required per input')
    keys, scripts, leaves = set(), set(), []

    def publish(data, xonly=False):
        if len(data) in ((32,) if xonly else (33, 65)):
            x = key_x(data)
            if x is not None:
                keys.add(x)

    def scan(script):
        for _, data in instructions(script):
            if data is not None:
                publish(data)

    def reveal(script):
        scripts.add(script)
        scan(script)

    for output in outputs:
        scan(output)
        if recognize(output).name == 'P2TR':
            publish(output[2:], True)
    for (coinbase, script_sig), witness, prevout in zip(inputs, witnesses, prevout_scripts):
        scan(script_sig)
        for element in witness:
            publish(element)
        if coinbase:
            continue
        kind = recognize(prevout, bip360_active).name
        if kind == 'P2SH' and bip16_active:
            pushes = [data for _, data in instructions(script_sig) if data is not None]
            if pushes:
                redeem = pushes[-1]
                reveal(redeem)
                if recognize(redeem).name == 'P2WSH':
                    if witness:
                        reveal(witness[-1])
        elif kind == 'P2WSH' and witness:
            reveal(witness[-1])
        elif kind == 'P2MR' or (kind == 'P2TR' and taproot_active):
            stack = witness
            if len(stack) >= 2 and stack[-1].startswith(b'\x50'):
                stack = stack[:-1]
            if len(stack) < 2:
                continue
            script, control = stack[-2:]
            base = 33 if kind == 'P2TR' else 1
            if len(control) < base or (len(control) - base) % 32:
                continue
            if (len(control) - base) // 32 > 128:
                continue
            if kind == 'P2MR' and not control[0] & 1:
                continue
            if kind == 'P2TR':
                publish(control[1:33], True)
            leaf = RevealedLeaf(control[0] & 254, script,
                                tuple(control[i:i + 32] for i in range(base, len(control), 32)))
            leaves.append(leaf)
            scan(script)
            if leaf.version == 192:
                ops = list(instructions(script))
                for (_, data), (next_op, _) in zip(ops, ops[1:]):
                    if data is not None and next_op in (172, 173, 186):
                        publish(data, True)
    return ChainEvidence(tuple(keys), tuple(scripts), tuple(leaves),
                         bip360_active=bip360_active)


_SPEC_SCRIPTS = [('P2PK, uncompressed key (genesis coinbase output script)',
  '4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac',
  'EXPOSED_AT_REST',
  False),
 ('P2PK, compressed key',
  '2102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9ac',
  'EXPOSED_AT_REST',
  False),
 ('P2PKH', '76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac', 'EXPOSED_ON_SPEND', False),
 ('Bare multisig, 1-of-2',
  '51210222222222222222222222222222222222222222222222222222222222222222222103333333333333333333333333333333333333333333333333333333333333333352ae',
  'EXPOSED_AT_REST',
  False),
 ('P2SH', 'a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba87', 'EXPOSED_ON_SPEND', False),
 ('P2WPKH (witness version 0, 20-byte program)',
  '001489abcdefabbaabbaabbaabbaabbaabbaabbaabba',
  'EXPOSED_ON_SPEND',
  False),
 ('P2WSH (witness version 0, 32-byte program)',
  '00201111111111111111111111111111111111111111111111111111111111111111',
  'EXPOSED_ON_SPEND',
  False),
 ("P2TR (witness version 1, 32-byte program; output key is the generator's x-coordinate)",
  '512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
  'EXPOSED_AT_REST',
  False),
 ('Witness version 1, 32-byte program that is not a valid x-coordinate',
  '5120ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
  'UNDETERMINED',
  False),
 ('Witness version 2, 32-byte program: P2MR where BIP 360 is active',
  '52201111111111111111111111111111111111111111111111111111111111111111',
  'EXPOSED_ON_SPEND',
  True),
 ('Witness version 2, 32-byte program: P2MR where BIP 360 is active (inactive)',
  '52201111111111111111111111111111111111111111111111111111111111111111',
  'UNDETERMINED',
  False),
 ('Witness version 1, 2-byte program (pay-to-anchor)', '51024e73', 'UNDETERMINED', False),
 ('Witness version 2, 16-byte program',
  '5210751e76e8199196d454941c45d1b3a323',
  'UNDETERMINED',
  False),
 ('Witness version 16, 40-byte program',
  '60285fbf4c95ba1cba1cba1cba1cba1cba1cba1cba1cba1cba1cba1cba1cba1cba1cba1cba1cba1cba1c',
  'UNDETERMINED',
  False)]

_G = bytes.fromhex('79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798')
_G2 = bytes.fromhex('c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5')


def _push(data):
    if len(data) <= 75:
        return bytes([len(data)]) + data
    if len(data) <= 255:
        return b'\x4c' + bytes([len(data)]) + data
    return b'\x4d' + len(data).to_bytes(2, 'little') + data


def _p2pkh(key):
    return b'\x76\xa9\x14' + hash160(key) + b'\x88\xac'


def _p2wpkh(key):
    return b'\x00\x14' + hash160(key)


def _p2sh(script):
    return b'\xa9\x14' + hash160(script) + b'\x87'


def _p2wsh(script):
    return b'\x00\x20' + hashlib.sha256(script).digest()


def _evidence_json(keys=(), scripts=(), leaves=(), count=0, complete=True, active=False):
    return {'published_keys': [k.hex() for k in keys],
            'revealed_scripts': [s.hex() for s in scripts],
            'revealed_leaves': [{'version': leaf.version, 'script': leaf.script.hex(),
                                 'path': [h.hex() for h in leaf.path]} for leaf in leaves],
            'own_spend_count': count, 'complete': complete, 'bip360_active': active}


def _load_evidence(data):
    return ChainEvidence(
        tuple(bytes.fromhex(k) for k in data['published_keys']),
        tuple(bytes.fromhex(s) for s in data['revealed_scripts']),
        tuple(RevealedLeaf(leaf['version'], bytes.fromhex(leaf['script']),
                           tuple(bytes.fromhex(h) for h in leaf['path']))
              for leaf in data['revealed_leaves']),
        data['own_spend_count'], data['complete'], data['bip360_active'])


def _fixture(label, description, script, expected, **kwargs):
    return {'id': label, 'description': description, 'script_pubkey': script.hex(),
            'evidence': _evidence_json(**kwargs), 'expected': expected}


def _serialize_tx(inputs, outputs):
    """Build fixture transactions from (coinbase, scriptSig, witness) inputs."""
    segwit = any(witness for _, _, witness in inputs)
    tx = b'\x02\x00\x00\x00' + (b'\x00\x01' if segwit else b'')
    tx += _compact_size(len(inputs))
    for coinbase, script, _ in inputs:
        tx += (b'\x00' * 32 + b'\xff' * 4 if coinbase else b'\x11' * 32 + b'\x00' * 4)
        tx += _compact_size(len(script)) + script + b'\xff' * 4
    tx += _compact_size(len(outputs))
    for script in outputs:
        tx += b'\x00' * 8 + _compact_size(len(script)) + script
    if segwit:
        for _, _, witness in inputs:
            tx += _compact_size(len(witness))
            for element in witness:
                tx += _compact_size(len(element)) + element
    return tx + b'\x00' * 4


def build_vectors():
    """Generate deterministic fixtures, including all hashes and transactions."""
    rest, spend, unknown = 'EXPOSED_AT_REST', 'EXPOSED_ON_SPEND', 'UNDETERMINED'
    k, k2 = b'\x02' + _G, b'\x02' + _G2
    multisig = b'\x52' + _push(k) + _push(k2) + b'\x52\xae'
    no_sig = b'\x51'
    leaf_script = _push(_G2) + b'\xac'
    leaf = RevealedLeaf(192, leaf_script, (hashlib.sha256(b'sibling').digest(),))
    root = leaf_hashes(leaf)[-1]
    scripts = [_fixture('S%02d' % i, desc, bytes.fromhex(raw), expected, active=active)
               for i, (desc, raw, expected, active) in enumerate(_SPEC_SCRIPTS, 1)]
    history = [
        _fixture('H01', 'P2PKH same script spent', _p2pkh(k), rest, count=1),
        _fixture('H02', 'P2PKH key in P2PK output', _p2pkh(k), rest, keys=(k,)),
        _fixture('H03', 'P2WPKH x-coordinate in P2TR output', _p2wpkh(k), rest, keys=(_G,)),
        _fixture('H04', 'P2SH-P2WPKH key published by P2WPKH spend', _p2sh(_p2wpkh(k)), rest, keys=(k,)),
        _fixture('H05', 'P2WSH script revealed through P2SH-P2WSH', _p2wsh(multisig), rest,
                 keys=(k, k2), scripts=(_p2wsh(multisig), multisig)),
        _fixture('H06', 'P2WSH revealed script needs no signature', _p2wsh(no_sig), rest, scripts=(no_sig,), count=None),
        _fixture('H07', 'P2WSH 2-of-2 keys published but script hidden', _p2wsh(multisig), spend, keys=(k, k2)),
        _fixture('H08', 'P2PKH no condition holds', _p2pkh(k), spend),
        _fixture('H09', 'P2PKH zero own spends and incomplete evidence', _p2pkh(k), unknown, complete=False),
        _fixture('H10', 'P2PKH positive count without retrieved spends', _p2pkh(k), rest, count=1, complete=False),
        _fixture('H11', 'P2MR root opened by P2TR leaf path', b'\x52\x20' + root, rest, keys=(_G2,), leaves=(leaf,), active=True),
        _fixture('H12', 'P2MR leaf key published but leaf hidden', b'\x52\x20' + root, spend, keys=(k2,), active=True),
    ]
    history[4]['classifications'] = [{'script_pubkey': _p2wpkh(k).hex(), 'expected': rest}]
    edges = []

    def edge(desc, script, expected, **kwargs):
        edges.append(_fixture('C%02d' % (len(edges) + 1), desc, script, expected, **kwargs))

    for encoding in key_encodings(_G):
        for target in (_p2pkh(encoding), _p2wpkh(encoding), _p2sh(_p2wpkh(encoding))):
            edge('Six-encoding expansion from x-only key', target, rest, keys=(_G,))
        edge('Accept each published encoding', _p2pkh(k), rest, keys=(encoding,))
    bad = b'\x02' + b'\xff' * 32
    for invalid in (bad, b'\x04' + _G + b'\x00' * 32,
                    b'\x07' + key_encodings(_G)[4][1:], b'\x05' + _G):
        edge('Invalid P2PK key', _push(invalid) + b'\xac', unknown)
        edge('Ignore invalid published key', _p2pkh(k), spend, keys=(invalid,))
    edge('Invalid P2TR x-coordinate', b'\x51\x20' + b'\xff' * 32, unknown)
    edge('Multisig too few valid keys', b'\x52' + _push(k) + _push(bad) + b'\x52\xae', unknown)
    edge('Multisig one valid key suffices', b'\x51' + _push(k) + _push(bad) + b'\x52\xae', rest)
    edge('Multisig counts positions', b'\x52' + _push(k) * 2 + b'\x52\xae', rest)
    edge('Multisig m zero with invalid key', b'\x00' + _push(bad) + b'\x51\xae', rest)
    edge('Multisig zero of zero', b'\x00\x00\xae', rest)
    edge('Multisig mismatched n', b'\x51' + _push(k) + b'\x52\xae', unknown)
    edge('Multisig m greater than n', b'\x52' + _push(k) + b'\x51\xae', unknown)
    edge('Truncated suffix after P2PK', _push(k) + b'\xac\x4c\xff\xac', unknown)
    edge('Non-minimal P2PK push', b'\x4c\x21' + k + b'\xac', rest)
    edge('Non-minimal multisig push', b'\x51\x4d\x21\x00' + k + b'\x51\xae', rest)
    edge('P2A', b'\x51\x02\x4e\x73', unknown)
    edge('OP_RETURN', b'\x6a' + _push(k), None)
    edge('Wrong-length witness v0', b'\x00\x02\x11\x22', None)
    edge('Non-direct witness program push', b'\x00\x4c\x14' + b'\x11' * 20, unknown)
    edge('Trailing witness byte', _p2wpkh(k) + b'\x00', unknown)
    for target in (_p2pkh(k), _p2wpkh(k), _p2sh(multisig), _p2wsh(multisig), b'\x52\x20' + root):
        edge('Positive own-spend count with partial evidence', target, rest, count=1, complete=False, active=True)
        edge('Zero count insufficient with partial evidence', target, unknown, complete=False, active=True)
        edge('Unknown count sufficient with complete evidence', target, spend, count=None, active=True)
    edge('Unassigned v2 ignores own spends', b'\x52\x20' + root, unknown, count=1)
    edge('P2SH direct revealed script', _p2sh(multisig), rest, keys=(k, k2), scripts=(multisig,))
    edge('P2SH nested P2WSH commitment', _p2sh(_p2wsh(multisig)), rest, keys=(k, k2), scripts=(multisig,))
    edge('Leaf bytes open P2SH', _p2sh(leaf.script), rest, keys=(_G2,), leaves=(leaf,))
    edge('Leaf bytes open nested P2WSH', _p2sh(_p2wsh(leaf.script)), rest, keys=(_G2,), leaves=(leaf,))
    edge('Leaf bytes open P2WSH', _p2wsh(leaf.script), rest, keys=(_G2,), leaves=(leaf,))
    edge('Partial key evidence establishes exposure', _p2pkh(k), rest, keys=(k,), complete=False)
    edge('Partial script evidence establishes exposure', _p2wsh(multisig), rest, scripts=(multisig,), complete=False)
    extraction = []

    def extraction_case(label, desc, prevout, script_sig, witness, keys=(), revealed=(), leaves=(),
                        outputs=(), targets=(), active=False, coinbase=False,
                        taproot_active=True, bip16_active=True, complete=False):
        tx = _serialize_tx([(coinbase, script_sig, witness)], outputs)
        expected = _evidence_json(keys, revealed, leaves, count=None, complete=False, active=active)
        extraction.append({'id': label, 'description': desc, 'tx': tx.hex(),
                           'prevout_scripts': [None if coinbase else prevout.hex()],
                           'bip360_active': active, 'taproot_active': taproot_active,
                           'expected_evidence': expected,
                           'classifications': [{'script_pubkey': s.hex(), 'expected': e}
                                               for s, e in targets]})
        if complete:
            extraction[-1]['classification_complete'] = True
        if not bip16_active:
            extraction[-1]['bip16_active'] = False

    extraction_case('E-a', 'P2WPKH spend publishes key', _p2wpkh(k), b'', (b'sig', k), keys=(k,),
                    targets=((_p2wpkh(k), rest),))
    extraction_case('E-b', 'P2WSH 2-of-2 reveals script and keys', _p2wsh(multisig), b'',
                    (b'', b'sig1', b'sig2', multisig), keys=(k, k2), revealed=(multisig,),
                    targets=((_p2wsh(multisig), rest),))
    hash_leaf = b'\xa8' + _push(_G2) + b'\x87'
    tr = b'\x51\x20' + _G
    control = b'\xc0' + _G
    extraction_case('E-c', 'Hash operand is not an x-only key', tr, b'', (hash_leaf, control),
                    keys=(_G,), leaves=(RevealedLeaf(192, hash_leaf),),
                    targets=((_p2wpkh(k2), unknown), (tr, rest)))
    extraction_case('E-d', 'Tapscript CHECKSIG publishes x-only key', tr, b'', (leaf_script, control),
                    keys=(_G, _G2), leaves=(RevealedLeaf(192, leaf_script),),
                    targets=((_p2wpkh(k2), rest),), taproot_active=True)
    extraction_case('E-e', 'OP_RETURN pushes a published key', b'\x51', b'', (), keys=(k,),
                    outputs=(b'\x6a' + _push(k),), targets=((_p2pkh(k), rest), (b'\x6a', None)))
    extraction_case('E-f', 'Coinbase scriptSig publishes key', None, _push(k), (), keys=(k,),
                    coinbase=True, targets=((_p2pkh(k), rest),))
    extraction_case('E-g', 'P2SH-P2WSH reveals both scripts', _p2sh(_p2wsh(multisig)),
                    _push(_p2wsh(multisig)), (b'', b'sig', multisig), keys=(k, k2),
                    revealed=(_p2wsh(multisig), multisig),
                    targets=((_p2sh(_p2wsh(multisig)), rest), (_p2wsh(multisig), rest)))
    depth_zero = RevealedLeaf(192, leaf_script)
    extraction_case('E-h', 'Active P2MR depth-zero reveals leaf', b'\x52\x20' + leaf_hashes(depth_zero)[0],
                    b'', (leaf_script, b'\xc1'), keys=(_G2,), leaves=(depth_zero,), active=True,
                    targets=((b'\x52\x20' + leaf_hashes(depth_zero)[0], rest),))
    extraction_case('E-i', 'P2TR path opens P2MR root', tr, b'', (leaf.script, control + b''.join(leaf.path)),
                    keys=(_G, _G2), leaves=(leaf,), active=True,
                    targets=((b'\x52\x20' + root, rest),))
    deep = RevealedLeaf(192, leaf_script, leaf.path + (hashlib.sha256(b'sibling2').digest(),))
    extraction_case('E-j', 'Intermediate branch matches but siblings do not', tr, b'',
                    (deep.script, control + b''.join(deep.path)), keys=(_G, _G2), leaves=(deep,), active=True,
                    targets=tuple((b'\x52\x20' + h, rest) for h in leaf_hashes(deep)) +
                            tuple((b'\x52\x20' + h, unknown) for h in deep.path))
    extraction_case('E-k', 'Annex stripped before path extraction', tr, b'',
                    (leaf_script, control, b'\x50annex'), keys=(_G, _G2), leaves=(depth_zero,),
                    targets=((_p2wpkh(k2), rest),))
    extraction_case('E-l', 'Malformed control block skipped', tr, b'', (leaf_script, b'\xc0' + _G + b'\x00'),
                    targets=((_p2wpkh(k2), unknown),))
    extraction_case('E-m', 'Inactive P2MR does not reveal leaf', b'\x52\x20' + root, b'', (leaf_script, b'\xc0'),
                    targets=((_p2wpkh(k2), unknown),))
    extraction_case('E-n', 'Unknown leaf version still reveals scripts and SEC keys', tr, b'',
                    (_push(k2) + _push(_G2) + b'\xac', b'\xc2' + _G), keys=(k, k2),
                    leaves=(RevealedLeaf(194, _push(k2) + _push(_G2) + b'\xac'),),
                    targets=((_p2wpkh(k2), rest),))
    extraction_case('E-o', 'Output key published; nested push data not rescanned', b'\x51', b'', (),
                    outputs=(b'\x51\x20' + _G2, _push(_push(k))), keys=(_G2,),
                    targets=((_p2wpkh(k2), rest), (_p2wpkh(k), unknown)))
    pushes = (b'\x00' + b'\x4c\x21' + k + b'\x4d\x21\x00' + k2 +
              b'\x4e\x21\x00\x00\x00' + k + b'\x4c\xff' + _push(bytes.fromhex(
                  '02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9')))
    extraction_case('E-p', 'Non-minimal pushes decoded until truncated push', b'\x51', pushes, (),
                    keys=(k, k2), targets=((_p2pkh(k), rest), (_p2pkh(k2), rest)))
    for op in (173, 186):
        script = b'\x4c\x20' + _G2 + bytes([op])
        extraction_case('E-q%d' % op, 'Non-minimal x-only push before signature opcode', tr, b'',
                        (script, control), keys=(_G, _G2), leaves=(RevealedLeaf(192, script),),
                        targets=((_p2wpkh(k2), rest),))
    extraction_case('E-r', 'Unknown leaf version excludes x-only signature operands', tr, b'',
                    (leaf_script, b'\xc2' + _G), keys=(_G,),
                    leaves=(RevealedLeaf(194, leaf_script),),
                    targets=((_p2wpkh(k2), unknown),))
    early = b'\x50' + _push(k2)
    extraction_case('E-s', 'OP_SUCCESS does not stop script decoding', tr, b'',
                    (early, control), keys=(_G, _G2), leaves=(RevealedLeaf(192, early),),
                    targets=((_p2wpkh(k2), rest),))
    mixed_tx = _serialize_tx([(False, _push(k), ()), (False, b'', (b'sig', k2))],
                             (b'\x6a' + _push(k),))
    extraction.append({'id': 'E-t', 'description': 'Mixed legacy and witness inputs',
                       'tx': mixed_tx.hex(), 'prevout_scripts': [b'\x51'.hex(), _p2wpkh(k2).hex()],
                       'bip360_active': False, 'taproot_active': True,
                       'expected_evidence': _evidence_json((k, k2), count=None, complete=False),
                       'classifications': [{'script_pubkey': _p2wpkh(k2).hex(), 'expected': rest}]})
    extraction_case('E-u', 'P2MR control byte with lowest bit clear reveals nothing',
                    b'\x52\x20' + leaf_hashes(depth_zero)[0], b'', (leaf_script, b'\xc0'), active=True,
                    targets=((b'\x52\x20' + leaf_hashes(depth_zero)[0], unknown),
                             (_p2wpkh(k2), unknown)))
    extraction_case('E-v', 'Inactive Taproot does not reveal leaf or internal key',
                    tr, b'', (leaf_script, control), taproot_active=False, complete=True,
                    targets=((_p2wpkh(k2), spend),))
    p2pk = _push(k) + b'\xac'
    extraction_case('E-w', 'Pre-BIP16 P2SH-shaped spend does not reveal discarded script',
                    _p2sh(b'\x01'), _push(p2pk) + b'\x75\x51', (),
                    bip16_active=False, complete=True,
                    targets=((_p2wpkh(k), spend), (_p2wsh(p2pk), spend)))
    extraction_case('E-w-wsh', 'Inactive P2SH excludes nested witness script but scans SEC keys',
                    _p2sh(_p2wsh(p2pk)), _push(k2) + _push(_p2wsh(p2pk)),
                    (k2, p2pk), keys=(k2,), bip16_active=False, complete=True,
                    targets=((_p2wpkh(k), spend), (_p2wsh(p2pk), spend), (_p2wpkh(k2), rest)))
    extraction_case('E-x-wpkh', 'Plain P2WPKH witness x-coordinate is not published',
                    _p2wpkh(k), b'', (_G,), complete=True,
                    targets=((_p2wpkh(k), spend),))
    extraction_case('E-x-wsh', 'Plain P2WSH witness x-coordinate is not published',
                    _p2wsh(no_sig), b'', (_G, no_sig), revealed=(no_sig,), complete=True,
                    targets=((_p2wpkh(k), spend),))
    extraction_case('E-x-sig', 'scriptSig x-coordinate push is not published',
                    b'\x51', _push(_G), (), complete=True,
                    targets=((_p2wpkh(k), spend),))
    extraction_case('E-x-output', 'Non-P2TR output x-coordinate push is not published',
                    b'\x51', b'', (), outputs=(_push(_G) + b'\xac',), complete=True,
                    targets=((_p2wpkh(k), spend),))
    extraction_case('E-y', 'Active P2MR depth-two path exposes computed hashes only',
                    b'\x52\x20' + leaf_hashes(deep)[-1], b'',
                    (deep.script, b'\xc1' + b''.join(deep.path)), keys=(_G2,),
                    leaves=(deep,), active=True, complete=True,
                    targets=tuple((b'\x52\x20' + h, rest) for h in leaf_hashes(deep)) +
                            tuple((b'\x52\x20' + h, spend) for h in deep.path))
    long_leaf = RevealedLeaf(192, b'\x61' * 252 + b'\x51')
    extraction_case('E-z', '253-byte leaf uses CompactSize fd fd 00',
                    b'\x52\x20' + leaf_hashes(long_leaf)[0], b'',
                    (long_leaf.script, b'\xc1'), leaves=(long_leaf,), active=True,
                    targets=((b'\x52\x20' + leaf_hashes(long_leaf)[0], rest),))
    return {'schema_version': 1, '_license': 'CC0-1.0',
            'script_vectors': scripts, 'history_vectors': history,
            'classification_vectors': edges, 'extraction_vectors': extraction,
            'extraction_notes': [
                'Extraction vectors are transaction-shaped parser fixtures, not valid confirmed transactions: signatures are not valid and Taproot output keys do not commit to their control blocks.',
                'Malformed-serialization and invalid-control-block vectors test defensive parsing beyond the specification.'],
            'appendix_a_actions': {level.value: action for level, action in ACTION.items()}}


def _level_name(level):
    return level.value if level is not None else None


def _run():
    checks = 0

    def check(ok, label):
        nonlocal checks
        checks += 1
        if not ok:
            raise AssertionError(label)

    vectors = build_vectors()
    with Path(__file__).with_name('test_vectors.json').open(encoding='utf-8') as f:
        check(json.load(f) == vectors, 'JSON differs from generated in-code vectors')
    for group in ('script_vectors', 'history_vectors', 'classification_vectors'):
        for vector in vectors[group]:
            evidence = _load_evidence(vector['evidence'])
            actual = classify(bytes.fromhex(vector['script_pubkey']), evidence)
            check(_level_name(actual) == vector['expected'], vector['id'] + ': ' + str(actual))
            for target in vector.get('classifications', ()):
                check(_level_name(classify(bytes.fromhex(target['script_pubkey']), evidence)) == target['expected'],
                      vector['id'] + ': classification differs')
    for vector in vectors['extraction_vectors']:
        extracted = extract_evidence(bytes.fromhex(vector['tx']),
                                     [None if s is None else bytes.fromhex(s)
                                      for s in vector['prevout_scripts']], vector['bip360_active'],
                                     taproot_active=vector['taproot_active'],
                                     bip16_active=vector.get('bip16_active', True))
        expected = _load_evidence(vector['expected_evidence'])
        check(extracted == expected, vector['id'] + ': extracted evidence differs')
        if vector.get('classification_complete', False):
            extracted = replace(extracted, complete=True)
        for target in vector['classifications']:
            check(_level_name(classify(bytes.fromhex(target['script_pubkey']), extracted)) == target['expected'],
                  vector['id'] + ': classification differs')
    for level, action in vectors['appendix_a_actions'].items():
        check(recommended_action(Level(level)) == action, 'action ' + level)
    for message, digest in ((b'', '9c1185a5c5e9fc54612808977ee8f548b2258d31'),
                            (b'abc', '8eb208f7e05d987a9b044a8e98c6b087f15a0bfc'),
                            (b'message digest', '5d0689ef49d2fae572b881b123a85ffa21595f36')):
        check(ripemd160_py(message).hex() == digest, 'RIPEMD-160 standard vector')
    if _hashlib_ripemd160():
        for size in (1, 55, 56, 63, 64, 65, 127, 128, 1000):
            message = bytes((7 * i + size) % 256 for i in range(size))
            check(ripemd160_py(message) == hashlib.new('ripemd160', message).digest(),
                  'RIPEMD-160 differential size ' + str(size))
    encodings = key_encodings(_G)
    check(len(set(encodings)) == 6 and all(key_x(k) == _G for k in encodings), 'six valid encodings')
    check(key_x(b'\x00' * 31 + b'\x05') is None, 'non-residue x-coordinate')
    check(list(instructions(b'\x00')) == [(0, b'')], 'OP_0 push')
    for broken in (b'\x4c', b'\x4d\x01', b'\x4e\x01\x00\x00', b'\x02\x01'):
        check(list(instructions(broken)) == [], 'incomplete push stops decoding')
    # Independent tagged-hash calculation fixes the domain separators and lengths.
    leaf = RevealedLeaf(192, b'\x51', (b'\x11' * 32, b'\x22' * 32))
    tag = hashlib.sha256(b'TapLeaf').digest()
    leaf_digest = hashlib.sha256(tag + tag + b'\xc0\x01\x51').digest()
    tag = hashlib.sha256(b'TapBranch').digest()
    branch = hashlib.sha256(tag + tag + min(leaf_digest, b'\x11' * 32) +
                            max(leaf_digest, b'\x11' * 32)).digest()
    root = hashlib.sha256(tag + tag + min(branch, b'\x22' * 32) +
                          max(branch, b'\x22' * 32)).digest()
    check(leaf_hashes(leaf) == (leaf_digest, branch, root), 'independent Merkle calculation')
    tx = _serialize_tx([(False, b'', ())], (b'\x51',))
    for broken in (tx[:-1], tx + b'\x00', tx[:4] + b'\x00\x02' + tx[4:]):
        try:
            extract_evidence(broken, [b'\x51'])
        except ValueError:
            check(True, 'reject malformed transaction')
        else:
            check(False, 'accepted malformed transaction')
    for count in range(1, len(tx)):
        try:
            extract_evidence(tx[:count], [b'\x51'])
        except ValueError:
            check(True, 'reject transaction truncation')
        else:
            check(False, 'accepted transaction truncation')
    counts = [len(vectors[group]) for group in ('script_vectors', 'history_vectors',
                                               'classification_vectors', 'extraction_vectors')]
    backend = 'hashlib' if HAVE_HASHLIB_RIPEMD160 else 'pure Python'
    print('Vectors: %d script, %d history, %d classification, %d extraction' % tuple(counts))
    print('Checks: %d passed; RIPEMD-160: %s' % (checks, backend))
    return 0


if __name__ == '__main__':
    raise SystemExit(_run())
