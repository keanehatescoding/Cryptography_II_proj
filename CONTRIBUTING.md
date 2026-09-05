# Contributing

This is an educational, from-scratch implementation of an authenticated
key exchange + encrypted channel protocol (see `README.md` for the full
design). Because it's crypto/security code, the bar for changes here is
a bit different from a typical app: a subtly wrong change can look like
it works while silently breaking a security property, so correctness
arguments and tests matter more than usual.

## Before you start

- For anything beyond a small fix, open an issue first describing the
  problem and your proposed approach. This avoids wasted work on a PR
  whose design doesn't fit the project.
- Check the existing issues (see labels below) - your bug or idea may
  already be tracked, sometimes with useful context.

## Reporting bugs / security findings

Everything in this repo is a local demo (loopback TCP, no production
deployment), so there is no coordinated-disclosure process - just open
a regular GitHub issue. Include:

- The file and line(s) involved.
- A concrete scenario: what input/sequence of actions triggers the
  problem, and what goes wrong (wrong output, crash, silently weaker
  guarantee, etc.) - "this looks unsafe" is much less actionable than
  "peer sends X, receiver does Y instead of Z".
- Whether you think it affects one of the properties in the README's
  "Why this design" table (forward secrecy, authentication, replay
  defense, ...) - findings that break a named security property get
  prioritized over style/robustness nits.

## Labels

| Label | Meaning |
| --- | --- |
| `security` | Weakens or breaks a security property (confidentiality, authentication, forward secrecy, replay/tamper detection, availability) |
| `bug` | Incorrect behavior that isn't specifically a security property |
| `enhancement` | New capability or a deliberate improvement to existing behavior |
| `documentation` | README/docstring/comment fixes |
| `priority: high` / `priority: medium` / `priority: low` | Rough triage of urgency/impact, orthogonal to the labels above |
| `good first issue` | Small, self-contained, doesn't require deep familiarity with the protocol internals |

## Development setup

```bash
pip install -r requirements.txt
python3 -m pytest -v
```

No virtual display is needed - the automated suite drives `PeerWorker`
(the networking/crypto layer `gui.py` sits on) directly over real
loopback sockets, without touching Tk widgets.

If you have `ruff` installed, run it before opening a PR:

```bash
ruff check .
```

CI currently only runs `pytest`; linting isn't enforced yet (tracked in
an open issue), but please don't add new violations in the files you
touch.

## Making changes

- **Match the existing style.** Docstrings in this codebase explain
  *why*, not *what* - a design decision, a threat being defended
  against, a trade-off that was made and why. If you add a non-obvious
  security-relevant choice, explain the reasoning the same way the
  surrounding code does.
- **Don't invent abstractions the task doesn't need.** A bug fix
  shouldn't grow into a refactor; a one-off script doesn't need a
  helper module. Keep diffs focused.
- **No feature flags or backwards-compat shims** for a project this
  size - just change the code and update its callers.
- **Validate at trust boundaries.** Code that parses bytes/JSON coming
  from an unauthenticated or not-yet-authenticated peer (`transport.py`,
  the handshake messages, file-transfer framing in `gui.py`) must treat
  that input as hostile: bound sizes, catch malformed input, and fail
  with a specific exception rather than letting a raw `KeyError` /
  `struct.error` / etc. propagate. Code operating on already-authenticated,
  decrypted plaintext can trust it more, since the AEAD tag already did
  that verification.

## Tests

- Any change to `crypto_utils.py`, `handshake.py`, `ratchet.py`,
  `secure_channel.py`, `padding.py`, `identity.py`, or `rate_limiter.py`
  needs a test demonstrating the new/fixed behavior - both the "this
  now works correctly" case and, where relevant, the "this attack/misuse
  is still rejected" case (see `test_secure_comms.py` for the existing
  pattern: tampering, replay, forged signatures, wrong passphrases,
  etc., are each their own explicit test).
- Changes to `gui.py`'s networking/file-transfer logic should have a
  corresponding test in `test_gui_file_transfer.py` or
  `test_gui_peerworker_integration.py` - both exercise `PeerWorker`
  without any Tk dependency, so they run in CI.
- Manual smoke-testing the Tk UI itself (tabs, notifications, dialogs)
  is fine to mention in the PR description instead of an automated
  test, since the widget layer isn't part of the automated suite today.

## Pull requests

- Keep PRs scoped to one issue/change. Small, reviewable PRs get
  merged faster, especially for security-sensitive files.
- Describe *why* the change is needed, not just what it does - link the
  issue it addresses.
- Make sure `python3 -m pytest -v` passes locally before opening the PR.
- Never commit real key material, trust-store files, or audit logs from
  local testing (`demo_keys/`, `gui_keys/`, `*.pem`, `*_history.enc`,
  `*_ratelimit.db*`, `*_audit.log` are gitignored - double check `git
  status` before pushing if you generated any of these while testing).
