```
  BIP: ?
  Layer: Applications
  Title: Output Public Key Exposure Classification
  Authors: duncan0k <duncan0k@cipherscope.io>
  Status: Draft
  Type: Specification
  Assigned: ?
  License: BSD-2-Clause OR CC0-1.0
  Version: 0.2.0
  Requires: 360
```

## Abstract

This document specifies a deterministic, conservative classification that assigns every Bitcoin
output an *exposure level* describing whether the public key material required to spend it has
already been published on-chain.

The classification depends only on data available from the block chain, is independent of any
wallet, indexer, or risk-scoring methodology, and is defined so that two independent
implementations observing the same chain state MUST produce the same result. It also defines
what an implementation MUST NOT infer, so that unknown or unobservable conditions can never be
reported as safe.

## Motivation

Two proposals now describe how Bitcoin may respond to a cryptographically relevant quantum
computer (CRQC): [BIP 360](bip-0360.mediawiki) defines an output type whose public key never
appears on-chain until it is spent, and BIP 361 proposes a phased migration that eventually
disables ECDSA and Schnorr verification for legacy outputs.

Both presuppose a capability that no BIP currently specifies: the ability to determine *which
existing outputs are exposed*. That gap is already producing observable harm.

**Published figures disagree because the definitions disagree.** Widely cited estimates of the
exposed supply range from roughly 25% to over 34%. The spread is not measurement error; it
follows from unstated definitional choices. Recurring points of divergence include:

* whether a P2TR output is exposed at rest, given that its 32-byte output key *is* a public key;
* whether an address that has been spent from, and still holds a balance, is treated as exposed
  at rest or only on spend;
* whether a P2SH or P2WSH output whose script has never been revealed can be classified at all;
* whether keys disclosed off-chain — via xpub sharing, or via spends of the corresponding output
  on a fork of the chain — fall within scope.

**The consequences are borne by users.** A holder who consults two wallets, two explorers, or two
custodians during a migration window can receive contradictory statements about the same coins.
If BIP 361 or a comparable proposal advances, "is this output legacy-vulnerable" becomes a
question with financial consequences, asked at scale, by software that must agree.

This BIP does not propose a consensus change, does not rank outputs by risk, and does not
recommend a migration policy. It specifies only the underlying observable: *has the key been
published, and by what mechanism*. Risk models, user-facing severity ratings, and migration
deadlines are left to their authors, who may then at least agree on the facts they are reasoning
about.

## Specification

The key words "MUST", "MUST NOT", "REQUIRED", "SHOULD", "SHOULD NOT", and "MAY" in this document
are to be interpreted as described in RFC 2119.

### Terminology

* **Key material** — a compressed or uncompressed secp256k1 public key, or an x-only public key
  as defined in [BIP 340](bip-0340.mediawiki). A 32-byte x-only key is key material: the full
  point is recoverable by selecting the even-`y` solution.
* **Published** — appearing in the block chain in any confirmed transaction, whether in a
  `scriptPubKey`, a `scriptSig`, or a witness stack.
* **Spending key set** of an output `O` — the set of public keys that must produce valid
  signatures in order to spend `O`. For script-based outputs, this set is not knowable from `O`
  alone before the script is revealed.
* **Disclosed** — an output `O` is disclosed if every member of a sufficient subset of its
  spending key set has been published. For an `m`-of-`n` multisig output, publication of any `m`
  of the `n` keys is sufficient.

Unconfirmed transactions MUST NOT be used to determine an exposure level. A transaction in the
mempool discloses key material to observers, but that disclosure is not yet a property of the
chain and may never become one. Implementations MAY report mempool disclosure separately; it is
outside this classification.

### Exposure Levels

Every output is assigned exactly one of four levels.

#### `EXPOSED_AT_REST`

The output is disclosed. A CRQC-equipped adversary can derive the spending key offline and spend
the output at a time of its choosing, without waiting for the legitimate owner to act. No
observable on-chain event gives the owner warning or an opportunity to react.

An output is `EXPOSED_AT_REST` if either condition holds:

1. **Structural** — its `scriptPubKey` contains key material directly.
2. **Derived** — key material sufficient to spend it was published by an earlier transaction,
   typically because the same key or script was previously used and spent from.

Both conditions produce the same adversarial capability and therefore the same level. An
implementation MUST NOT assign a lesser level to a reused, previously-spent script merely because
the key was disclosed by a spend rather than by the `scriptPubKey`.

#### `EXPOSED_ON_SPEND`

The output is not disclosed, but spending it will necessarily publish key material. The adversary
has no offline attack. The exposure window opens when a spending transaction is broadcast and
closes when it is confirmed and buried; within that window, an adversary capable of deriving the
key faster than the transaction confirms may replace it.

#### `NOT_EXPOSED`

The output is not disclosed, and spending it does not publish key material capable of spending
any other output. This level is reachable only by output types designed with that property, such
as P2MR ([BIP 360](bip-0360.mediawiki)), where a script-path spend reveals only the leaf actually
executed.

#### `UNDETERMINED`

The output's script semantics are not recognized by the implementation, and no sound statement
about its key material can be made.

`UNDETERMINED` MUST be assigned rather than `NOT_EXPOSED` whenever an output cannot be classified.
An implementation that has not been updated for an output type deployed after its release will
encounter such outputs; reporting them as unexposed would state a safety property the
implementation has not established. This level exists so that the classification degrades
correctly rather than optimistically as the chain evolves.

### Conservative Assignment

Implementations MUST apply the **fail-closed rule**: where available data is insufficient to
distinguish between two levels, the level indicating greater disclosure MUST be assigned.

A classifier that reports an output as less exposed than the chain warrants provides false
assurance to a holder who may act on it. A classifier that errs toward greater exposure prompts
an unnecessary migration. These errors are not symmetric, and the specification is not neutral
between them.

Consequences that follow from this rule:

* Failure to parse a script MUST NOT clear an exposure level that has already been established by
  other evidence.
* Truncated or partial transaction history MUST NOT yield `NOT_EXPOSED`; see
  [Classification Under Partial History](#classification-under-partial-history).
* Output types not recognized by the implementation MUST yield `UNDETERMINED`.

### Classification by Output Type

The following table gives the level of an output that has *not* been disclosed by any earlier
transaction. The derived condition of `EXPOSED_AT_REST` overrides every row: an output for which
*everything required to construct a valid spend* — sufficient keys, and for script-committing
types the script itself — has been published elsewhere is `EXPOSED_AT_REST` regardless of its
type.

| Output type | On-chain commitment | Level absent prior disclosure |
| --- | --- | --- |
| P2PK | public key, in full | `EXPOSED_AT_REST` |
| P2MS (bare multisig) | all `n` public keys, in full | `EXPOSED_AT_REST` |
| P2PKH | `HASH160` of the key | `EXPOSED_ON_SPEND` |
| P2WPKH | `HASH160` of the key | `EXPOSED_ON_SPEND` |
| P2SH | `HASH160` of the redeem script | `EXPOSED_ON_SPEND` |
| P2WSH | `SHA256` of the witness script | `EXPOSED_ON_SPEND` |
| P2TR | 32-byte x-only output key | `EXPOSED_AT_REST` |
| P2MR ([BIP 360](bip-0360.mediawiki)) | 32-byte `TapBranch` Merkle root | `NOT_EXPOSED` |
| Other witness versions / programs | undetermined | `UNDETERMINED` |
| Non-standard or unparsable | undetermined | `UNDETERMINED` |

Three rows warrant explicit statement.

**P2TR is `EXPOSED_AT_REST`, including script-path-only outputs.** A Taproot output commits the
tweaked output key `Q = P + H(P‖m)·G` in the clear. An adversary who solves the discrete logarithm
of `Q` obtains a private key that satisfies key-path verification directly. Consensus does not
check how `Q` was constructed, so committing to a provably-unspendable internal key (a NUMS point)
does not prevent this: the output remains spendable by anyone who can solve for `Q`. Removing this
property is precisely the design goal of BIP 360.

**P2SH and P2WSH are `EXPOSED_ON_SPEND`, not `NOT_EXPOSED`.** The script is unknown before it is
revealed, so no claim can be made about its key material — but every spend reveals the script in
full, and every script that requires a signature reveals key material with it. The fail-closed
rule therefore assigns `EXPOSED_ON_SPEND`. A P2SH or P2WSH output committing to a script that
requires no signature would in fact be unexposed, but this is unobservable before the spend and
MUST NOT be assumed.

**P2MR is `NOT_EXPOSED` only for its own outputs.** A script-path spend publishes the leaf script
that was executed, and any keys in it. Those keys become disclosed, and any *other* output whose
spending key set they satisfy is thereby `EXPOSED_AT_REST` by the derived condition. The
`NOT_EXPOSED` level is a property of the unspent output, not a permanent property of its keys.

Note that publication of a leaf key alone does not make a P2MR output disclosed: spending a P2MR
output additionally requires the leaf script and its Merkle path, neither of which is observable
from the output. The derived condition applies to a P2MR output only when a complete spend
recipe has been published — in practice, when an output committing to the *same* script tree was
previously spent through a leaf whose keys are disclosed. An implementation cannot observe the
leaves of a never-spent tree, so a classifier restricted to chain data will report such an
output `NOT_EXPOSED`; this is the intended reading of the levels as statements about what the
chain shows (see [Out-of-Band Disclosure](#out-of-band-disclosure)).

### Classification Under Partial History

An implementation that cannot retrieve the complete transaction history of a script — because of
indexer pagination limits, scan budgets, or pruning — MUST NOT conclude `NOT_EXPOSED` from the
absence of a spend in the retrieved subset.

Where an implementation has access to aggregate output statistics for a script, the following
inference is sound and requires no history traversal:

> If the script has a confirmed spent-output count greater than zero, at least one spend has
> occurred. For every type in the table above other than P2MR and `UNDETERMINED`, a spend
> publishes the material committed to by the script — the key for key-committing types, the full
> script (and any keys it contains) for script-committing types. The script is therefore
> disclosed, and all of its outputs are `EXPOSED_AT_REST` by the derived condition.

For a script-hash output whose revealed script requires no signature, this floor over-approximates
— no key material was actually published. The error is in the conservative direction, which the
fail-closed rule permits; an implementation that retrieves the revealing transaction SHOULD
refine the level from the actual script content.

This yields a classification in constant time from an aggregate counter, and remains correct as a
lower bound when history retrieval is truncated. Implementations SHOULD use it as a floor:
retrieved transactions then serve to identify *which* keys were disclosed and *when*, refining
the evidence without being able to weaken the level.

The rules above apply to outputs whose classification depends on spend history — those that would
otherwise be `EXPOSED_ON_SPEND`. Structural assignment needs no history at all: a P2PK or P2TR
output is `EXPOSED_AT_REST` from its `scriptPubKey` alone, and an unrecognized type is
`UNDETERMINED` regardless of what history shows. Where a history-dependent classification is
required but neither complete history nor aggregate statistics are available, the implementation
MUST report `UNDETERMINED` rather than a level derived from an admittedly incomplete view.

### Indexer Blind Spots

Address-indexed APIs commonly index outputs by the address encoded in their `scriptPubKey`. P2PK
and bare P2MS outputs encode no address, and such indexers frequently omit them from the history
of the corresponding P2PKH address, even where the same key controls both.

An implementation relying on an address-indexed data source therefore cannot observe P2PK
disclosure for a key it is examining, and may report `EXPOSED_ON_SPEND` for a key whose full
public key has been on-chain since 2009. Implementations SHOULD additionally query by script
hash where the data source permits, and MUST document this limitation where it does not.

### Out-of-Band Disclosure

The following disclose key material without producing evidence on the Bitcoin chain, and are
therefore outside this classification. Implementations MUST NOT report `NOT_EXPOSED` or
`EXPOSED_ON_SPEND` as an assertion that no disclosure has occurred; the levels describe only what
the chain shows.

* **Fork-chain spends** — spending an output on a chain sharing Bitcoin's UTXO history publishes
  the public key there, exposing the corresponding unspent Bitcoin output.
* **Extended public key disclosure** — an xpub shared with a service provider discloses every
  child key derivable from it, including keys for outputs never spent on any chain.
* **Sidechain, bridge, and cross-protocol reuse** of the same key.
* **Compromise or publication by any party holding the key.**

Implementations that can observe such disclosure through other means SHOULD surface it as a
separate signal, distinctly labelled as not chain-derived.

### Test Vectors

Vectors are given at script level so that they may be verified without network access. Each is a
`scriptPubKey` in hex, with the level required for an output paying to it that has no prior
disclosure.

Every public key appearing below is a valid secp256k1 point, so that implementations performing
point validation accept these vectors. Where a 32-byte value is a hash rather than a key — the
P2WSH witness script hash and the P2MR Merkle root — an arbitrary value is used, as any 32-byte
string is well-formed in those positions.

```
# P2PK, uncompressed key (genesis coinbase output script)
4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac
=> EXPOSED_AT_REST

# P2PK, compressed key
2102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9ac
=> EXPOSED_AT_REST

# P2PKH
76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac
=> EXPOSED_ON_SPEND

# P2MS, 1-of-2 bare multisig
5121022222222222222222222222222222222222222222222222222222222222222222
  21033333333333333333333333333333333333333333333333333333333333333333
  52ae
=> EXPOSED_AT_REST

# P2SH
a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba87
=> EXPOSED_ON_SPEND

# P2WPKH (witness v0, 20-byte program)
001489abcdefabbaabbaabbaabbaabbaabbaabbaabba
=> EXPOSED_ON_SPEND

# P2WSH (witness v0, 32-byte program)
00201111111111111111111111111111111111111111111111111111111111111111
=> EXPOSED_ON_SPEND

# P2TR (witness v1, 32-byte program; output key is the generator's x-coordinate)
512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
=> EXPOSED_AT_REST

# P2MR (witness v2, 32-byte program, BIP 360)
52201111111111111111111111111111111111111111111111111111111111111111
=> NOT_EXPOSED

# Witness v2, 16-byte program — valid per BIP 350, semantics unassigned
5210751e76e8199196d454941c45d1b3a323
=> UNDETERMINED

# Witness v16, 40-byte program — valid per BIP 350, semantics unassigned
60285fbf4c95ba1cba1cba1cba1cba1cba1cba1cba1cba1cba1cba1cba1cba1cba1cba1cba1cba1cba1c
=> UNDETERMINED
```

History-dependent vectors, which require chain state rather than a script alone:

| Condition | Required level |
| --- | --- |
| P2PKH script, one or more confirmed spends, balance remains | `EXPOSED_AT_REST` |
| P2WSH script, one or more confirmed spends, balance remains | `EXPOSED_AT_REST` |
| P2PKH script, no confirmed spend, retrieved history truncated | `EXPOSED_ON_SPEND` |
| P2PKH script, no confirmed spend, complete history available | `EXPOSED_ON_SPEND` |
| P2TR script, no transactions at all | `EXPOSED_AT_REST` |
| P2MR script, script-path spend occurred, revealed leaf key reused elsewhere | revealed key's other outputs become `EXPOSED_AT_REST` |
| Hash-committed script (e.g. P2PKH), aggregate statistics unavailable, history incomplete | `UNDETERMINED` |

## Rationale

**Why four levels rather than two.** A binary exposed/not-exposed split conflates two adversarial
situations that call for different responses. An `EXPOSED_AT_REST` holder is under a standing
threat and must move funds to a quantum-resistant output. An `EXPOSED_ON_SPEND` holder is not
under threat while the output sits unspent, but faces a race at the moment of spending; the
mitigations differ, and so must the labels. The fourth level, `UNDETERMINED`, is required by the
fail-closed rule rather than by any distinction in risk.

**Why disclosure mechanism does not change the level.** An earlier formulation of this
classification treated structural exposure (P2PK, P2TR) and reuse-derived exposure (a spent-from
P2PKH retaining a balance) as distinct levels. They are not distinct to an adversary: in both
cases the key is on-chain and the coins can be taken without warning. Separating them invites the
reading that reused addresses are safer than P2PK, which is false. Implementations that wish to
report the mechanism SHOULD do so as an additional attribute, not by weakening the level.

**Why no scoring.** Converting exposure into a numeric risk score requires weighing balance,
dormancy, owner sophistication, and assumptions about CRQC timelines — all of which are contested
and none of which are observable on-chain. Standardizing the observable while leaving the weighing
to implementers is what makes independent results comparable. This BIP deliberately stops at the
fact.

**Why the aggregate-counter floor is specified.** Naively, establishing exposure requires scanning
a script's full history for a spend, which is unbounded work for heavily-used scripts and
impossible for many light clients. The floor reduces the common case to reading one counter, and —
more importantly — it is the reason a truncated scan cannot produce a false `NOT_EXPOSED`. Without
it, every implementation must independently decide what to report when it runs out of scan budget,
and the divergence this BIP exists to remove reappears at the engineering layer.

**Relationship to BIP 361.** BIP 361 proposes to stop accepting new outputs to legacy types, then
to disable legacy signature verification. Its phases are defined over output *types*, which
consensus can evaluate directly. This BIP addresses the question consensus does not answer and
wallets must: given an output of a legacy type, has its key already been published, and how
urgently must this particular holder act. The two are complementary; neither depends on the other
being adopted.

**Relationship to BIP 360.** BIP 360 supplies the destination for migration and is the only
currently-proposed output type reaching `NOT_EXPOSED`. This BIP requires it only to classify P2MR
outputs; the remainder applies unchanged if BIP 360 is never activated.

## Backward Compatibility

This BIP introduces no consensus, policy, or peer-to-peer protocol change. It defines an
observation over existing chain data, and no existing software becomes non-compliant by not
implementing it.

Software that currently reports exposure under a different taxonomy will find its output changes
in two respects on adopting this specification: reused, previously-spent scripts that retain a
balance move from an on-spend classification to `EXPOSED_AT_REST`, and unrecognized output types
move from an unexposed classification to `UNDETERMINED`. Both changes are in the conservative
direction. Implementations SHOULD version their reports so that consumers can distinguish
classifications produced before and after adoption.

## Reference Implementation

A self-contained implementation in Python, with no dependencies beyond the standard library, is
available at:

    https://github.com/duncan0k/pubkey-exposure-classification

It implements the level assignment, the fail-closed combinator, the derived-disclosure condition,
and the constant-time floor, and executes every vector in this document — both script-level and
history-dependent — when run directly. The vectors are additionally published there as
`test_vectors.json` under CC0-1.0 for use by implementations in other languages.

## Changelog

* 0.2.0 — Clarified that the derived condition requires a complete spend recipe, and how it
  applies (and does not apply) to P2MR outputs; scoped the partial-history `UNDETERMINED` rule to
  history-dependent classifications, since structural assignment needs no history; noted that the
  aggregate-counter floor over-approximates for revealed scripts requiring no signature, and that
  the error is in the conservative direction; removed an impossible `NOT_EXPOSED` mention from
  the indexer blind-spot discussion.
* 0.1.0 — Initial draft.

## Copyright

This document is licensed under the BSD 2-Clause License and, at the recipient's option, under
CC0 1.0 Universal. The test vectors are additionally placed under CC0 1.0 Universal so that they
may be copied into implementations without licensing friction.
