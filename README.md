# AURAL — Open Audio Evidence Container

**Early working prototype, not a released industry standard.** Proposed extension: `.aural`.

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

Read [`docs/SPECIFICATION-0.1-DRAFT.md`](docs/SPECIFICATION-0.1-DRAFT.md) for package details and limitations.

The `examples/` folder contains `sample.wav` (generated silence) and `sample.aural` (sample package). Both are synthetic test fixtures, not investigation evidence.

### Current integrity guarantee

The verifier checks archive structure and independently re-hashes the packaged WAV against its manifest. **It cannot authenticate a recorder, investigator, real-world event, or the manifest itself.** Future signature profiles will address identity assertions and tampering with manifest + payload together, subject to trusted keys.

### Design principles

Preserve original bytes; independently verifiable evidence; open implementation; interpretation-neutral; future extensibility; minimal reader requirements.

## License

MIT for implementation and repository text (see `LICENSE`). We may later choose a dedicated specification license/governance charter for long-term open-standard stewardship.
