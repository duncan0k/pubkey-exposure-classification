#!/usr/bin/env python3
"""Reference implementation for the Output Public Key Exposure Classification BIP.

Self-contained; no dependencies beyond the standard library. Run directly to
execute the test vectors from the BIP text:

    python3 exposure_classification.py

SPDX-License-Identifier: BSD-2-Clause OR CC0-1.0
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Set


class Level(str, Enum):
    """Exposure levels, ordered from most to least disclosed.

    The ordering matters: the fail-closed rule resolves ambiguity by selecting
    the *lower* index, i.e. the level indicating greater disclosure.
    """

    EXPOSED_AT_REST = "EXPOSED_AT_REST"
    #: Safe at rest; key material is published only when spent. Read carefully:
    #: this is NOT "already exposed". EXPOSED_WHEN_SPENT is under consideration
    #: as a clearer name (see the draft's Rationale); treat both as synonyms.
    EXPOSED_ON_SPEND = "EXPOSED_ON_SPEND"
    UNDETERMINED = "UNDETERMINED"
    #: Reserved for output types whose consensus rules require a post-quantum
    #: signature on every spending path, hybrid schemes included. No deployed
    #: type qualifies; P2MR is EXPOSED_ON_SPEND.
    NOT_EXPOSED = "NOT_EXPOSED"


_ORDER = [
    Level.EXPOSED_AT_REST,
    Level.EXPOSED_ON_SPEND,
    Level.UNDETERMINED,
    Level.NOT_EXPOSED,
]


def most_exposed(*levels: Level) -> Level:
    """Fail-closed combinator: return the level indicating greatest disclosure."""
    return min(levels, key=_ORDER.index)


#: Appendix A (informative): fixed action key per level. Wallets own the
#: wording, reasons and urgency; this is the floor they should not contradict.
ACTION = {
    Level.EXPOSED_AT_REST: "MIGRATE",
    Level.EXPOSED_ON_SPEND: "SWEEP_WHEN_SPENDING",
    Level.NOT_EXPOSED: "NONE",
    Level.UNDETERMINED: "TREAT_AS_MIGRATE",
}


def recommended_action(level: Level) -> str:
    """Return the Appendix A action key for a level."""
    return ACTION[level]


# --------------------------------------------------------------------------
# Script recognition
# --------------------------------------------------------------------------

OP_0 = 0x00
OP_1 = 0x51
OP_16 = 0x60
OP_DUP = 0x76
OP_EQUAL = 0x87
OP_EQUALVERIFY = 0x88
OP_HASH160 = 0xA9
OP_CHECKSIG = 0xAC
OP_CHECKMULTISIG = 0xAE


@dataclass(frozen=True)
class ScriptType:
    name: str
    #: Key material sits in the scriptPubKey itself; exposed from the moment
    #: the output is created.
    structural: bool
    #: Spending this output publishes secp256k1 key material: the key for
    #: key-committing types, the script and its keys for script-committing
    #: types, the executed leaf with its path and key for P2MR. True for every
    #: recognized type.
    discloses_on_spend: bool
    #: The implementation understands this template's key semantics. When false,
    #: no sound statement can be made and UNDETERMINED is required.
    recognized: bool = True
    #: Public keys extractable from the scriptPubKey, as hex strings.
    keys: tuple = field(default=())
    #: HASH160 of the public key the output commits to (P2PKH, P2WPKH), as hex.
    #: Lets the derived condition match a key published elsewhere.
    key_hash: Optional[str] = None
    #: Every spending path the type's consensus rules allow requires a
    #: post-quantum signature, hybrid schemes included. No deployed type has it.
    pq_signature_required: bool = False


def _witness_program(script: bytes) -> Optional[tuple]:
    """Return (version, program) if `script` is a witness program, else None.

    Follows BIP 141 with the BIP 350 length rules: version 0 or 1..16, program
    length 2..40, and the push opcode must match the program length exactly.
    """
    if len(script) < 4 or len(script) > 42:
        return None
    head = script[0]
    if head == OP_0:
        version = 0
    elif OP_1 <= head <= OP_16:
        version = head - (OP_1 - 1)
    else:
        return None
    push = script[1]
    program = script[2:]
    if push != len(program) or not (2 <= len(program) <= 40):
        return None
    return version, program


def recognize(script: bytes) -> ScriptType:
    """Classify a scriptPubKey into a known template, or an unrecognized one."""
    n = len(script)

    # P2PK: <push 33|65> <pubkey> OP_CHECKSIG
    if n in (35, 67) and script[0] in (0x21, 0x41) and script[-1] == OP_CHECKSIG:
        if script[0] + 2 == n:
            return ScriptType("P2PK", True, True, keys=(script[1:-1].hex(),))

    # P2PKH: OP_DUP OP_HASH160 <push 20> <hash> OP_EQUALVERIFY OP_CHECKSIG
    if (
        n == 25
        and script[0] == OP_DUP
        and script[1] == OP_HASH160
        and script[2] == 0x14
        and script[23] == OP_EQUALVERIFY
        and script[24] == OP_CHECKSIG
    ):
        return ScriptType("P2PKH", False, True, key_hash=script[3:23].hex())

    # P2SH: OP_HASH160 <push 20> <hash> OP_EQUAL
    if n == 23 and script[0] == OP_HASH160 and script[1] == 0x14 and script[22] == OP_EQUAL:
        return ScriptType("P2SH", False, True)

    # P2MS: OP_m <pubkey pushes> OP_n OP_CHECKMULTISIG
    if n >= 4 and script[-1] == OP_CHECKMULTISIG:
        if OP_1 <= script[0] <= OP_16 and OP_1 <= script[-2] <= OP_16:
            m = script[0] - (OP_1 - 1)
            declared_n = script[-2] - (OP_1 - 1)
            keys, i = [], 1
            while i < n - 2:
                push = script[i]
                if push not in (0x21, 0x41) or i + 1 + push > n - 2:
                    keys = None
                    break
                keys.append(script[i + 1 : i + 1 + push].hex())
                i += 1 + push
            if keys is not None and i == n - 2 and len(keys) == declared_n and m <= declared_n:
                return ScriptType(f"P2MS-{m}of{declared_n}", True, True, keys=tuple(keys))

    wp = _witness_program(script)
    if wp is not None:
        version, program = wp
        if version == 0 and len(program) == 20:
            return ScriptType("P2WPKH", False, True, key_hash=program.hex())
        if version == 0 and len(program) == 32:
            return ScriptType("P2WSH", False, True)
        if version == 1 and len(program) == 32:
            # The 32-byte output key is an x-only public key (BIP 340). Solving
            # its discrete log yields a working key-path spend regardless of how
            # the internal key was chosen, so a NUMS internal key does not help.
            return ScriptType("P2TR", True, True, keys=(program.hex(),))
        if version == 2 and len(program) == 32:
            # BIP 360 P2MR: the program is a TapBranch Merkle root, not a key, so
            # nothing is exposed at rest. A leaf spend still publishes the leaf's
            # secp256k1 key with the leaf and its Merkle path: exposed on spend.
            return ScriptType("P2MR", False, True)
        # Valid witness program, semantics unassigned.
        return ScriptType(
            f"witness-v{version}-{len(program)}B", False, False, recognized=False
        )

    return ScriptType("unrecognized", False, False, recognized=False)


# --------------------------------------------------------------------------
# Hashing and secp256k1 points
# --------------------------------------------------------------------------

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


#: secp256k1 field prime; the curve is y^2 = x^3 + 7.
_P = 2**256 - 2**32 - 977


def _lift_x(x: int) -> Optional[int]:
    """Return a y with (x, y) on secp256k1, or None if x is not a coordinate."""
    if x >= _P:
        return None
    y2 = (pow(x, 3, _P) + 7) % _P
    y = pow(y2, (_P + 1) // 4, _P)
    return y if y * y % _P == y2 else None


def _disclosed_x(key_hex: str) -> Optional[int]:
    """x-coordinate of a disclosed key (33, 65 or 32 bytes), or None if invalid."""
    try:
        raw = bytes.fromhex(key_hex)
    except (TypeError, ValueError):
        return None
    if len(raw) == 33 and raw[0] in (2, 3):
        x = int.from_bytes(raw[1:], "big")
    elif len(raw) == 65 and raw[0] == 4:
        x = int.from_bytes(raw[1:33], "big")
        y = _lift_x(x)
        # The given y must be one of the two roots, not just any 32 bytes.
        if y is None or int.from_bytes(raw[33:], "big") not in (y, _P - y):
            return None
        return x
    elif len(raw) == 32:
        x = int.from_bytes(raw, "big")
    else:
        return None
    return x if _lift_x(x) is not None else None


def _serializations(x: int) -> List[bytes]:
    """Every compressed and uncompressed encoding of the two points with this x."""
    y = _lift_x(x)
    assert y is not None
    xb = x.to_bytes(32, "big")
    return [
        b"\x02" + xb,
        b"\x03" + xb,
        b"\x04" + xb + y.to_bytes(32, "big"),
        b"\x04" + xb + (_P - y).to_bytes(32, "big"),
    ]


def _key_hash_disclosed(key_hash: str, disclosed_keys: Set[str]) -> bool:
    """True if a disclosed key, or its negation, hashes to `key_hash`.

    Solving the discrete log of P also gives the key of -P, and the hash commits
    to one encoding while the adversary can produce any, so match on x alone.
    """
    target = bytes.fromhex(key_hash)
    for key in disclosed_keys:
        x = _disclosed_x(key)
        if x is not None and any(hash160(s) == target for s in _serializations(x)):
            return True
    return False


# --------------------------------------------------------------------------
# Chain state
# --------------------------------------------------------------------------


@dataclass
class ChainState:
    """What the classifier knows about a script's confirmed history.

    `spent_output_count` is the aggregate counter that makes the constant-time
    floor possible. `history_complete` records whether the full transaction
    history was retrievable; `disclosed_keys` holds key material observed
    published elsewhere, enabling the derived condition.
    """

    spent_output_count: Optional[int] = None
    history_complete: bool = False
    disclosed_keys: Set[str] = field(default_factory=set)


def classify(script: bytes, state: Optional[ChainState] = None) -> Level:
    """Assign an exposure level to an output paying to `script`."""
    state = state or ChainState()
    t = recognize(script)

    # 1. Post-quantum types (none deployed): a derived secp256k1 private key
    #    alone cannot spend the output, so this precedes every rule below.
    if t.pq_signature_required:
        return Level.NOT_EXPOSED

    # 2. Structural disclosure: key material is in the scriptPubKey itself.
    if t.structural:
        return Level.EXPOSED_AT_REST

    # 3. Unrecognized semantics: nothing sound can be said. Checked before the
    #    history rules, because a spend of an unknown script does not
    #    demonstrably publish key material either.
    if not t.recognized:
        return Level.UNDETERMINED

    # 4. Derived disclosure: a key that can spend this output was published
    #    elsewhere. Same adversarial capability as structural disclosure.
    #    P2SH, P2WSH and P2MR would also need the committed script (for P2MR,
    #    the leaf and its Merkle path), which ChainState does not carry; for
    #    them only the floor below and the script's own history apply.
    if t.discloses_on_spend and state.disclosed_keys & set(t.keys or ()):
        return Level.EXPOSED_AT_REST
    if t.key_hash is not None and _key_hash_disclosed(t.key_hash, state.disclosed_keys):
        return Level.EXPOSED_AT_REST

    # 5. Constant-time floor: a confirmed spend has occurred, and for every
    #    disclosing type a spend publishes key material. Correct even when
    #    history retrieval was truncated.
    if t.discloses_on_spend and state.spent_output_count is not None:
        if state.spent_output_count > 0:
            return Level.EXPOSED_AT_REST
        return Level.EXPOSED_ON_SPEND

    # 6. Neither aggregate statistics nor complete history: refuse to guess.
    if not state.history_complete:
        return Level.UNDETERMINED

    return Level.EXPOSED_ON_SPEND


# --------------------------------------------------------------------------
# Test vectors
# --------------------------------------------------------------------------

# Script-level vectors: no prior disclosure, complete history, unspent.
_FRESH = ChainState(spent_output_count=0, history_complete=True)

SCRIPT_VECTORS = [
    # P2PK, uncompressed key (genesis coinbase output script)
    ("4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649"
     "f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac",
     Level.EXPOSED_AT_REST),
    # P2PK, compressed key
    ("2102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9ac",
     Level.EXPOSED_AT_REST),
    # P2PKH
    ("76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac",
     Level.EXPOSED_ON_SPEND),
    # P2MS, 1-of-2 bare multisig
    ("5121022222222222222222222222222222222222222222222222222222222222222222"
     "21033333333333333333333333333333333333333333333333333333333333333333"
     "52ae",
     Level.EXPOSED_AT_REST),
    # P2SH
    ("a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba87",
     Level.EXPOSED_ON_SPEND),
    # P2WPKH
    ("001489abcdefabbaabbaabbaabbaabbaabbaabbaabba",
     Level.EXPOSED_ON_SPEND),
    # P2WSH
    ("00201111111111111111111111111111111111111111111111111111111111111111",
     Level.EXPOSED_ON_SPEND),
    # P2TR (output key is the generator's x-coordinate)
    ("512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
     Level.EXPOSED_AT_REST),
    # P2MR (BIP 360)
    ("52201111111111111111111111111111111111111111111111111111111111111111",
     Level.EXPOSED_ON_SPEND),
    # Witness v2, 16-byte program — valid per BIP 350, semantics unassigned
    ("5210751e76e8199196d454941c45d1b3a323", Level.UNDETERMINED),
    # Witness v16, 40-byte program
    ("60285fbf4c95ba1cba1cba1cba1cba1cba1cba1cba1cba1cba1cba1cba1cba1cba1cba"
     "1cba1cba1cba1c", Level.UNDETERMINED),
]

P2PKH = bytes.fromhex("76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac")
P2WSH = bytes.fromhex("00201111111111111111111111111111111111111111111111111111111111111111")
P2TR = bytes.fromhex("512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
P2MR = bytes.fromhex("52201111111111111111111111111111111111111111111111111111111111111111")

HISTORY_VECTORS = [
    ("P2PKH, spent from, balance remains",
     P2PKH, ChainState(spent_output_count=3, history_complete=True), Level.EXPOSED_AT_REST),
    ("P2WSH, spent from, balance remains",
     P2WSH, ChainState(spent_output_count=1, history_complete=True), Level.EXPOSED_AT_REST),
    ("P2PKH, no spend, history truncated",
     P2PKH, ChainState(spent_output_count=0, history_complete=False), Level.EXPOSED_ON_SPEND),
    ("P2PKH, no spend, complete history",
     P2PKH, ChainState(spent_output_count=0, history_complete=True), Level.EXPOSED_ON_SPEND),
    ("P2TR, no transactions at all",
     P2TR, ChainState(spent_output_count=0, history_complete=True), Level.EXPOSED_AT_REST),
    ("P2MR, unspent",
     P2MR, ChainState(spent_output_count=0, history_complete=True), Level.EXPOSED_ON_SPEND),
    ("P2MR, spent from, balance remains",
     P2MR, ChainState(spent_output_count=1, history_complete=True), Level.EXPOSED_AT_REST),
    ("P2PKH, no aggregate stats and incomplete history",
     P2PKH, ChainState(spent_output_count=None, history_complete=False), Level.UNDETERMINED),
]


def _run() -> int:
    failures = 0

    for hex_script, expected in SCRIPT_VECTORS:
        script = bytes.fromhex(hex_script)
        got = classify(script, _FRESH)
        name = recognize(script).name
        ok = got == expected
        failures += not ok
        print(f"{'PASS' if ok else 'FAIL'}  {name:<22} {got.value:<18} expected {expected.value}")

    print()
    for label, script, state, expected in HISTORY_VECTORS:
        got = classify(script, state)
        ok = got == expected
        failures += not ok
        print(f"{'PASS' if ok else 'FAIL'}  {label:<48} {got.value:<18} expected {expected.value}")

    # The derived condition: a key disclosed elsewhere exposes this output too.
    print()
    tr_key = P2TR[2:].hex()
    reused = ChainState(spent_output_count=0, history_complete=True, disclosed_keys={tr_key})
    got = classify(P2TR, reused)
    ok = got == Level.EXPOSED_AT_REST
    failures += not ok
    print(f"{'PASS' if ok else 'FAIL'}  derived: key disclosed elsewhere  -> {got.value}")

    # Fail-closed combinator.
    got = most_exposed(Level.NOT_EXPOSED, Level.EXPOSED_ON_SPEND, Level.UNDETERMINED)
    ok = got == Level.EXPOSED_ON_SPEND
    failures += not ok
    print(f"{'PASS' if ok else 'FAIL'}  fail-closed combinator            -> {got.value}")

    # Appendix A: every level has exactly one action key.
    expected_actions = {"EXPOSED_AT_REST": "MIGRATE", "EXPOSED_ON_SPEND": "SWEEP_WHEN_SPENDING",
                        "NOT_EXPOSED": "NONE", "UNDETERMINED": "TREAT_AS_MIGRATE"}
    for lvl in Level:
        ok = recommended_action(lvl) == expected_actions[lvl.value]
        failures += not ok
        print(f"{'PASS' if ok else 'FAIL'}  action {lvl.value:<18} -> {recommended_action(lvl)}")

    total = len(SCRIPT_VECTORS) + len(HISTORY_VECTORS) + 2 + len(Level)
    print(f"\n{total} vectors, {failures} failing")
    return 1 if failures else 0


# --------------------------------------------------------------------------
# Implementation checks (not part of the published vectors)
# --------------------------------------------------------------------------

#: The generator G and 2G, compressed and uncompressed.
_G_X = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
_G_Y = "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
_2G_X = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
G_COMPRESSED = "02" + _G_X
G_NEGATED = "03" + _G_X
G_UNCOMPRESSED = "04" + _G_X + _G_Y
TWO_G_COMPRESSED = "02" + _2G_X


def _p2pkh(pubkey_hex: str) -> bytes:
    return bytes.fromhex("76a914") + hash160(bytes.fromhex(pubkey_hex)) + bytes.fromhex("88ac")


def _p2wpkh(pubkey_hex: str) -> bytes:
    return bytes.fromhex("0014") + hash160(bytes.fromhex(pubkey_hex))


def _on_curve(pubkey_hex: str) -> bool:
    """Check a key directly against y^2 = x^3 + 7, independent of _disclosed_x."""
    raw = bytes.fromhex(pubkey_hex)
    x = int.from_bytes(raw[1:33], "big")
    y = _lift_x(x)
    if y is None:
        return False
    if len(raw) == 65:
        y = int.from_bytes(raw[33:], "big")
    elif raw[0] == 3:
        y = _P - y
    return x < _P and y < _P and (y * y - pow(x, 3, _P) - 7) % _P == 0


def _run_checks() -> int:
    failures = 0
    count = 0

    def check(label: str, ok: bool, detail: str = "") -> None:
        nonlocal failures, count
        count += 1
        failures += not ok
        print(f"{'PASS' if ok else 'FAIL'}  {label:<48} {detail}")

    print("\nImplementation checks")
    print()
    check("keys used below are on secp256k1",
          all(_on_curve(k) for k in (G_COMPRESSED, G_NEGATED, G_UNCOMPRESSED, TWO_G_COMPRESSED)))

    def derived(label: str, script: bytes, keys: Set[str], expected: Level) -> None:
        state = ChainState(spent_output_count=0, history_complete=True, disclosed_keys=keys)
        try:
            got = classify(script, state).value
        except Exception as exc:  # a malformed entry must never raise
            got = f"raised {type(exc).__name__}"
        check(label, got == expected.value, f"{got:<18} expected {expected.value}")

    derived("P2PKH(K), K disclosed compressed",
            _p2pkh(G_COMPRESSED), {G_COMPRESSED}, Level.EXPOSED_AT_REST)
    derived("P2PKH(K uncompressed), K disclosed compressed",
            _p2pkh(G_UNCOMPRESSED), {G_COMPRESSED}, Level.EXPOSED_AT_REST)
    derived("P2WPKH(K), K disclosed x-only",
            _p2wpkh(G_COMPRESSED), {_G_X}, Level.EXPOSED_AT_REST)
    derived("P2PKH(-K), K disclosed",
            _p2pkh(G_NEGATED), {G_COMPRESSED}, Level.EXPOSED_AT_REST)
    derived("P2PKH(K), unrelated key disclosed",
            _p2pkh(G_COMPRESSED), {TWO_G_COMPRESSED}, Level.EXPOSED_ON_SPEND)
    malformed = {
        "", "zz", "abc", "02", "05" + _G_X, "02" + _G_X + "00",
        "04" + _G_X + "00" * 32,  # right x, y not on the curve
        "02" + "ff" * 32,  # x beyond the field prime
        "02" + "00" * 31 + "05",  # x = 5 has no y on secp256k1
        "00" * 31 + "05",
    }
    derived("P2PKH(K), malformed and off-curve keys disclosed",
            _p2pkh(G_COMPRESSED), malformed, Level.EXPOSED_ON_SPEND)

    standard = [
        (b"", "9c1185a5c5e9fc54612808977ee8f548b2258d31"),
        (b"abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"),
        (b"message digest", "5d0689ef49d2fae572b881b123a85ffa21595f36"),
    ]
    for msg, digest in standard:
        got = ripemd160_py(msg).hex()
        check(f"ripemd160_py({msg!r})", got == digest, got)
    if HAVE_HASHLIB_RIPEMD160:
        lengths = (1, 55, 56, 63, 64, 65, 127, 128, 1000)
        msgs = [bytes((7 * i + n) % 256 for i in range(n)) for n in lengths]
        check(f"ripemd160_py matches hashlib, lengths {lengths[1:6]} etc.",
              all(ripemd160_py(m) == hashlib.new("ripemd160", m).digest() for m in msgs))
    else:
        print("SKIP  ripemd160_py vs hashlib: hashlib has no ripemd160")

    print(f"\n{count} implementation checks, {failures} failing")
    return 1 if failures else 0


if __name__ == "__main__":
    vectors_failed = _run()
    checks_failed = _run_checks()
    raise SystemExit(1 if vectors_failed or checks_failed else 0)
