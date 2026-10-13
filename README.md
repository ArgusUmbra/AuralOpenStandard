# AURAL — Open Audio Evidence Container

**Draft 0.2 proposal, not a released industry standard.** Proposed extension: `.aural`.

Aural Umbra is intended to be the first application built around this independently implementable format, not a prerequisite for using it.

## Requirements

Python 3.10+; no third-party dependencies.

## Run from the repository root

```powershell
python -m aural pack "recording.wav" "investigation.aural" --title "Field session"
python -m aural verify "investigation.aural"
python -m aural extract "investigation.aural" "recovered.wav"
python -m unittest discover -s tests -v
```

Read [`docs/SPECIFICATION-0.2-DRAFT.md`](docs/SPECIFICATION-0.2-DRAFT.md) for the proposed normative profile, [`docs/CONFORMANCE.md`](docs/CONFORMANCE.md) for test vectors, and [`docs/INTEROPERABILITY.md`](docs/INTEROPERABILITY.md) for porting guidance. Draft 0.1 remains documented and readable through a distinct legacy path.

The `examples/` folder contains the original Draft 0.1 synthetic sample. Draft 0.2 positive and negative fixtures are under `tests/fixtures/conformance/`. None is investigation evidence.

### Current integrity guarantee

The verifier checks archive structure and independently re-hashes the packaged WAV against its manifest. **It cannot authenticate a recorder, investigator, real-world event, or the manifest itself.** Future signature profiles will address identity assertions and tampering with manifest + payload together, subject to trusted keys.

### Interoperability check

```powershell
python -m unittest discover -s tests -v
node interop\validate_aural.mjs tests\fixtures\conformance\valid-minimal.aural
```

The Python implementation writes Draft 0.2 and reports Draft 0.1 packages as legacy. The independent Node validator covers the classic-size Draft 0.2 conformance corpus; it does not yet implement ZIP64.

### Design principles

Preserve original bytes; independently verifiable evidence; open implementation; interpretation-neutral; future extensibility; minimal reader requirements.

## License

MIT for implementation and repository text (see `LICENSE`). We may later choose a dedicated specification license/governance charter for long-term open-standard stewardship.
