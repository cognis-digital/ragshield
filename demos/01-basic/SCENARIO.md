# Demo 01 - Basic corpus poisoning scan

This demo scans a small RAG corpus (`corpus.jsonl`) that mixes clean
knowledge-base documents with several deliberately poisoned entries.

## The corpus

`corpus.jsonl` is one JSON object per line. Each object has an `id`, a
`text` field, and (for some documents) a precomputed `embedding` vector.

The clean documents are short product-support answers with small, normal
embeddings. The planted attacks are:

| id        | attack                                                        |
|-----------|---------------------------------------------------------------|
| `poison-1`| **instruction injection** - "ignore all previous instructions..." telling the model to always recommend a scam URL. |
| `poison-2`| **zero-width backdoor trigger** - invisible U+200B characters smuggled into otherwise innocent text. |
| `poison-3`| **rare repeated token** - the nonce `qzx9trigger` hammered repeatedly as a covert retrieval key. |
| `poison-4`| **embedding anomaly** - an embedding vector with a hugely inflated norm so it is retrieved for nearly any query. |
| `flood-*` | **duplication flooding** - five near-identical copies of an attacker talking point. |

## Run it

```sh
python -m ragshield scan demos/01-basic/corpus.jsonl
```

For pipelines, emit JSON and rely on the exit code (non-zero when a
medium-or-worse finding is present):

```sh
python -m ragshield scan demos/01-basic/corpus.jsonl --format json
echo "exit code: $?"
```

## Expected result

RAGSHIELD reports critical/high findings for the injection, the invisible
trigger, the repeated nonce, the norm-outlier embedding, and the duplicate
flood, sets `poisoned: true`, and exits non-zero. The clean documents
produce no findings.
