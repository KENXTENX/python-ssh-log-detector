# Architecture

```text
synthetic/approved OpenSSH log -> parser -> UTC events
-> exact-line deduplication -> chronological sort
-> per-IP sliding window -> rule SSH-001 alerts / JSON
```

Detection is a heuristic, not proof of compromise. The window includes its endpoint; a second alert requires the window to drop below the threshold first.

Input logs may contain sensitive user and host data. Only sanitized synthetic fixtures are committed. Traditional syslog timezones are ambiguous: the --legacy-year option explicitly supplies a year and the initial implementation interprets this legacy format as UTC. A future production integration should use normalized journald or SIEM events with explicit timestamps.

Limitations: batch memory processing; no continuous tailing, no central ingestion, no detection of all authentication methods, and no prevention. False positives can come from shared NATs and automation errors; distributed low-frequency attempts can evade the rule.
