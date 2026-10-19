# Public Key Exposure Classification

A deterministic, conservative classification that assigns every Bitcoin output an *exposure
level* describing whether the public key required to spend it has already been published
on-chain.

The draft specification is
[`bip-output-pubkey-exposure-classification.md`](bip-output-pubkey-exposure-classification.md);
this repository also carries its reference implementation and test vectors. The draft has not
been assigned a BIP number and is not a ratified standard — it is published here to gather
feedback before being proposed to the BIPs repository, per
[BIP 3](https://github.com/bitcoin/bips/blob/master/bip-0003.md).

Discussion is on the [Bitcoin Development Mailing List](https://groups.google.com/g/bitcoindev)
and [Delving Bitcoin](https://delvingbitcoin.org/t/2866). Corrections and objections are welcome
as issues here or replies there.

## Why

[BIP 360](https://github.com/bitcoin/bips/blob/master/bip-0360.mediawiki) defines the two attacks
this classification is built on, long exposure and short exposure, and lists which output types
are vulnerable to the first. BIP 361 proposes a phased sunset of legacy signature verification.
Between them sits the question tools disagree on: for a given output, what counts as revealed,
and what to report when the chain cannot be read in full.

The gap is visible in published data. Estimates of the exposed supply range from roughly 25% to
over 34%. The spread is definitional, not measurement error: implementations disagree on whether
a Taproot output is exposed at rest, whether a spent-from address that retains a balance differs
from P2PK, and what to report for a script whose contents have never been revealed.

## Levels

| Level | Meaning | Action key (Appendix A) |
| --- | --- | --- |
| `EXPOSED_AT_REST` | The key is on-chain. An adversary can derive it offline and spend at will. | `MIGRATE` |
| `EXPOSED_ON_SPEND` | The key is not on-chain, but spending will publish it. | `SWEEP_WHEN_SPENDING` |
| `NOT_EXPOSED` | The output type's consensus rules require a post-quantum signature on every spending path, hybrid schemes included. No deployed type qualifies; P2MR is `EXPOSED_ON_SPEND`. | `NONE` |
| `UNDETERMINED` | Script semantics unrecognized; no sound statement can be made. | `TREAT_AS_MIGRATE` |

The action keys are an informative floor requested by wallet developers: wallets own the wording,
reasons and urgency, but should not contradict the substance.

Two rules distinguish this from an ad-hoc taxonomy:

**Fail-closed.** Where available data cannot distinguish two levels, the level indicating greater
disclosure is assigned. A classifier that under-reports gives false assurance to someone who may
act on it; one that over-reports prompts an unnecessary migration. The errors are not symmetric.

**Disclosure mechanism does not change the level.** A reused, spent-from script that retains a
balance is `EXPOSED_AT_REST`, the same as P2PK — to an adversary they are the same situation.

## Usage

```python
from exposure_classification import classify, ChainState, Level

script = bytes.fromhex("76a914" + "89abcdef" * 5 + "88ac")  # P2PKH

classify(script, ChainState(spent_output_count=0, history_complete=True))
# Level.EXPOSED_ON_SPEND

classify(script, ChainState(spent_output_count=3, history_complete=True))
# Level.EXPOSED_AT_REST  — a spend published the key
```

The `spent_output_count` field carries an aggregate counter available from most indexers. It is
what makes classification constant-time, and — more importantly — it is why a truncated history
scan cannot produce a false `NOT_EXPOSED`.

## Running the vectors

```
python3 exposure_classification.py
```

No dependencies beyond the standard library. Vectors are also available as
[`test_vectors.json`](test_vectors.json) for use by implementations in other languages.

## Scope

This project classifies. It does not score, rank, or advise. Turning exposure into a risk number
requires weighing balance, dormancy and CRQC timelines — none observable on-chain, all contested.
Standardizing the observable while leaving the weighing to implementers is what makes independent
results comparable.

Out-of-band disclosure — xpubs shared with service providers, spends of the corresponding output
on a fork — is outside the classification by construction, since it leaves no evidence on the
Bitcoin chain. A `NOT_EXPOSED` result asserts what the chain shows, not that no disclosure has
occurred.

## License

BSD-2-Clause OR CC0-1.0, at your option. The test vectors are additionally placed under CC0-1.0
so they may be copied into implementations without licensing friction.
