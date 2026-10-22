# Evidence checklist

Status: implementation underway. This repository includes synthetic fixtures only; no live intrusion detection result is claimed.

- [ ] CI unit-test and smoke jobs verified for reviewed PR.
- [ ] Clone reviewed code into Ubuntu and run tests there.
- [ ] Confirm CLI produces a single SSH-001 alert for the fixture.
- [ ] Confirm --fail-on-alert exits 1 by design.
- [ ] Record redacted testing environment and exact test counts.
- [ ] Review the limitations and make a safe false-positive scenario.
- [ ] Merge only after reviewing code and CI results.

Keep real addresses, SSH usernames, hostnames, logs and passwords out of public GitHub evidence.
