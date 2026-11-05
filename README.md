# Public Key Exposure Classification

Reference implementation and test vectors for [BIP 362 version 0.7.0](bip-0362.md), which assigns a Bitcoin
output one of four exposure levels with respect to an adversary who can compute discrete
logarithms on secp256k1, for example with a quantum computer. The draft was assigned BIP number
362 in [bitcoin/bips#2294](https://github.com/bitcoin/bips/pull/2294), but it is not a ratified
standard.

Discussion is on the [Bitcoin Development Mailing List](https://groups.google.com/g/bitcoindev)
and [Delving Bitcoin](https://delvingbitcoin.org/t/2866). Corrections and objections are welcome
as issues here or replies there.

## Levels

See [BIP 362](bip-0362.md) for the full rules.

| Level | When | Action (Appendix A) |
| --- | --- | --- |
| `EXPOSED_AT_REST` | Enough valid keys are in the output (see below), a revealed script opens its commitment, or, for P2PKH, P2WPKH and P2SH-P2WPKH outputs, its key has been published on the chain. | `MIGRATE` |
| `EXPOSED_ON_SPEND` | A P2PKH, P2WPKH, P2SH, P2WSH or active P2MR output meets none of those conditions, checked against every confirmed transaction. Spending it reveals its key or script. | `SWEEP_WHEN_SPENDING` |
| `NOT_EXPOSED` | The output type requires a post-quantum signature for every spend. No deployed type qualifies. | `NONE` |
| `UNDETERMINED` | The script is not recognized, it lacks the valid keys required below, or the data needed for another level is missing. | `MIGRATE` |

P2PK and P2TR require a valid public key. Bare multisig requires valid keys in at least `m`
of its key positions; `m = 0` needs none. Otherwise these types are `UNDETERMINED`.
Levels apply only at evaluated blocks where BIP 16, BIP 141 and BIP 341 are active.
Outputs beginning with `OP_RETURN` and witness version 0 programs of lengths other than 20 or
32 bytes are not classified (`classify` returns `None`). P2MR is `UNDETERMINED` until BIP 360
is active. Revealed leaves expose P2MR roots matching their leaf hash or any computed branch
hash along their Merkle path, but not sibling hashes alone.

## Usage

```python
from exposure_classification import ChainEvidence, classify

p2pkh = bytes.fromhex("76a914" + "89abcdef" * 5 + "88ac")

classify(p2pkh, ChainEvidence(own_spend_count=0, complete=True))
# Level.EXPOSED_ON_SPEND: nothing in the evidence exposes it

classify(p2pkh, ChainEvidence(own_spend_count=3))
# Level.EXPOSED_AT_REST: a confirmed spend of this script published its key

classify(p2pkh, ChainEvidence(own_spend_count=0))
# Level.UNDETERMINED: the key may have been published under another script
```

`extract_evidence` collects the published keys, revealed scripts and revealed leaves of one
confirmed transaction. Pass the activation states of the block containing the spending transaction:

```python
from exposure_classification import extract_evidence

evidence = extract_evidence(
    tx, prevout_scripts,
    bip16_active=spending_block_bip16_active,
    taproot_active=spending_block_bip341_active,
    bip360_active=spending_block_bip360_active,
)
```

These historical states differ from `ChainEvidence.bip360_active`, which controls P2MR
classification at the evaluated block. The extractor returns partial evidence with its
`bip360_active` field set to the supplied spending-block state; set the evaluated-block state
when combining snapshots. Combining every confirmed transaction in the evaluated block and its
ancestors, and deciding whether the evidence is complete, is left to the caller. There is no
BIP 141 switch: blocks before BIP 141 carry no witness data, so nothing is revealed from a
witness there. Exclude
unconfirmed transactions and other blocks. A positive `own_spend_count` must count only spends
in blocks where the output type's consensus rules were active. Extraction does not verify
signatures or commitments.

## Running the vectors

```
python3 exposure_classification.py
```

No dependencies beyond the standard library. The vectors are also in
[`test_vectors.json`](test_vectors.json) for implementations in other languages.

Extraction vectors are transaction-shaped parser fixtures: their signatures are not valid and
their Taproot output keys do not commit to their control blocks. They are not valid confirmed
transactions. Malformed-serialization and invalid-control-block vectors test defensive parsing
beyond the specification.

## License

BSD-2-Clause OR CC0-1.0, at your option. The test vectors are additionally placed under CC0-1.0.
