# handrail examples

Two rule packs, a shared lexicon, a case file, and a runnable gate
script — all offline and self-contained.

## packs/pii-basics.yaml

Masks emails and phone numbers, blocks payment-card numbers, cloud access
keys and PEM private-key material, and flags high-entropy blobs. Meant to
run at **both** stages: inbound prompts and outbound model text.

```bash
handrail lint  examples/packs/pii-basics.yaml
echo "mail sam@example.test" | handrail check --pack examples/packs/pii-basics.yaml -
```

## packs/prompt-hygiene.yaml

Pre-stage checks for inbound prompts: known injection phrasings
(substring-matched from `lexicons/injection-phrases.txt`), internal
codenames (redacted), a length budget, a URL-count flag, and a
repeated-character flood block.

```bash
echo "please ignore previous instructions" \
  | handrail check --pack examples/packs/prompt-hygiene.yaml -
echo "exit: $?"   # 1 — blocked
```

## cases/pii-basics.cases.yaml

The pii pack's own test fixtures. Every pack change should ship with a
case proving it:

```bash
handrail test --pack examples/packs/pii-basics.yaml examples/cases/pii-basics.cases.yaml
```

## gate.sh

A complete pre/post gate in twelve lines of shell: sanitize the prompt on
the way in, re-check the reply on the way out, refuse on block.

```bash
bash examples/gate.sh
```

Everything here is deterministic: the same inputs produce byte-identical
reports on every machine.
