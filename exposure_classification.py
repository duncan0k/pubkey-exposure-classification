#!/usr/bin/env python3
"""Reference implementation for the Output Public Key Exposure Classification BIP.

Self-contained; no dependencies beyond the standard library. Run directly to
execute the test vectors from the BIP text:

    python3 exposure_classification.py

SPDX-License-Identifier: BSD-2-Clause OR CC0-1.0
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Set


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
        return ScriptType("P2PKH", False, True)

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
            return ScriptType("P2WPKH", False, True)
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
    if t.discloses_on_spend and state.disclosed_keys & set(t.keys or ()):
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


if __name__ == "__main__":
    raise SystemExit(_run())
