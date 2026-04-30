# Binary Analysis Toolkit: Analyst Guide

This guide is the short companion to the project README. Use it when you need to triage a suspicious PE quickly and decide whether to escalate.

## Start Here

Use the path that matches your role:

- SOC analyst: confirm severity, extract IOCs, scope affected hosts, escalate when needed
- CERT or IR analyst: contain, scope, and decide whether the sample indicates active compromise
- Threat hunter: convert IOCs and behaviors into fleet-wide searches

## Role-Based Playbooks

### SOC Triage

1. Run BAT on the sample.
2. Read the verdict and highest-severity rule.
3. Review hashes, `imphash`, and IOCs.
4. Check entropy and likely packing.
5. Escalate if the sample suggests execution, theft, persistence, or impact.

### CERT / Incident Response

1. Determine whether the sample executed on a host.
2. Use BAT IOCs to scope endpoints, users, and outbound traffic.
3. Prioritize credential theft, exfiltration, persistence, and destructive behaviors.
4. Contain affected hosts and revoke exposed credentials or tokens.
5. Decide whether deeper sandboxing or reverse engineering is required.

### Threat Hunting Follow-Up

1. Promote hashes, domains, URLs, paths, and registry keys into hunts.
2. Search for related samples with `imphash`.
3. Hunt for persistence artifacts and outbound communications.
4. Correlate the sample with email, web proxy, EDR, and DNS telemetry.
5. Expand the hunt when lateral movement or shared infrastructure is present.

## Triage Workflow

### 1. Run basic analysis

```bash
uv run binanalysis sample.exe
```

BAT saves `sample_analysis.json` and `sample_analysis.html` next to the file.

### Sample output

```text
CLASSIFICATION: LIKELY MALICIOUS

Highest severity findings:
  - browser_credential_theft (critical)
  - discord_webhook_exfil (critical)

Top IOCs:
  - hxxps://discord[.]com/api/webhooks/...
  - %LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data

Section summary:
  - .text entropy: 7.42
```

Read it in this order:

1. `CLASSIFICATION`
2. Highest-severity behavior
3. IOCs
4. Entropy and section anomalies

### 2. Check the verdict first

| Verdict | Meaning | Action |
| ------- | ------- | ------ |
| `MALICIOUS` | Strong direct indicators | Escalate, quarantine, begin IR if executed |
| `LIKELY MALICIOUS` | Multiple high-confidence indicators | Treat as high priority and validate context |
| `SUSPICIOUS` | Concerning but not conclusive | Investigate source, purpose, and environment |
| `No strong indicators` | Static analysis found little | Do not treat as clean, especially if packed |

If the sample executed on a host, combine the verdict with host telemetry before closing.

### 3. Look up hashes

- Search the `SHA256` in VirusTotal or your TI platform
- Search the `imphash` for related samples
- Record whether the sample is known, unknown, or rare in your environment

### 4. Review IOCs

Use extracted URLs, domains, file paths, registry keys, tokens, and credentials for:

- Proxy or firewall blocks
- SIEM or EDR hunting
- Credential revocation
- Scoping affected hosts

If tokens, session material, or credentials appear in the report, treat them as exposed until proven otherwise.

### 5. Read behavioral findings

Treat the rules as evidence of capability, not proof of execution. Focus on categories that change response urgency:

- Injection
- Credential theft
- Persistence
- Exfiltration
- Impact or ransomware behavior
- Rootkit or driver activity

Quick handling guide:

| Finding type | Typical meaning | Immediate action |
| ------------ | --------------- | ---------------- |
| Injection | Offensive process tampering | Escalate and review process telemetry |
| Credential theft | Theft of secrets or session data | Reset passwords, revoke sessions, scope affected user |
| Persistence | Survives reboot | Hunt and remove persistence artifacts |
| Exfiltration | Data leaving the host | Review outbound traffic and possible disclosure |
| Ransomware or wiper | Destructive impact | Isolate host and begin containment immediately |
| Lateral movement | Spread to other systems | Hunt across adjacent hosts and shares |

If X then Y:

- High entropy plus no imports: move to sandboxing and do not suppress as benign.
- Browser theft plus webhook or bot exfiltration: reset passwords, revoke sessions, review outbound traffic, and scope the user.
- Persistence plus dropped path or registry key: hunt the same artifact fleet-wide.
- Injection plus suspicious child process activity: review process trees and memory telemetry.
- Ransom text, shadow-copy deletion, or mass deletion: isolate the host immediately.
- Driver loading or physical memory access: treat as critical and prefer reimage planning over simple cleanup.

### 6. Check for packing

High-entropy sections, tiny import tables, and limited strings often mean the sample is packed. In that case:

- Static findings are incomplete
- Strings may belong only to the unpacker stub
- Dynamic analysis is usually the next step

### 7. Go deeper only when needed

```bash
uv run binanalysis sample.exe --decompile ghidra
uv run binanalysis sample.exe --decompile both
```

Ghidra output is filtered to suspicious functions so the report stays usable.

## Reading the Findings

### Hashes

Start with `SHA256` for reputation lookups and case tracking. Use `imphash` to cluster related builds.

Analyst action:

- Known bad: block and scope immediately
- Unknown but suspicious: continue triage, keep sample for detonation
- Known good internally: verify signer, path, and delivery context before suppressing

### Sections and entropy

- Around `5.0` to `6.5`: common for ordinary code
- `6.5` to `7.0`: elevated, possibly compressed or obfuscated
- Above `7.0`: often packed or encrypted

Also pay attention to writable and executable sections, or sections with zero raw size but non-zero virtual size.

Analyst action:

- Entropy above `7.0`: assume packing or encryption and queue sandboxing
- `WRITE+EXECUTE`: treat as strong suspicion, especially with injection or shellcode indicators
- Minimal imports plus high entropy: do not close on a weak verdict

### Imports

Imports often reveal intent quickly. Injection APIs, browser credential access, network libraries, and process-launch APIs matter more than generic runtime imports.

Analyst action:

- Injection or hollowing APIs: escalate
- Browser, wallet, or token-access APIs: assume data theft risk
- Downloader or socket APIs: check for C2 and payload retrieval

### Strings

Strings are the fastest source of actionable intelligence. Prioritize:

- URLs and domains
- File and registry paths
- Embedded credentials or tokens
- Ransom notes or payment references
- Browser, wallet, or messaging-app targets

Analyst action:

- URLs and domains: block and hunt
- Credentials and tokens: revoke
- Paths and registry keys: search fleet-wide
- Ransom text or payment artifacts: treat as destructive malware

### Behavioral rules

The rules combine imports, strings, entropy, and other context. A fired rule usually matters more than any single raw signal.

High-value categories:

- `Injection`: almost always offensive
- `Credential access`: assume secrets are compromised if the sample ran
- `Persistence`: remove both the file and the persistence mechanism
- `Exfiltration`: check whether data already left the network
- `Impact`: ransomware or wiper indicators demand immediate containment
- `Lateral movement`: broaden the hunt beyond one endpoint

Use the highest-severity rule to drive your first response action, then use the IOC section to scope impact.

### JSON fields for automation

Common fields to promote into SIEM or case tooling:

- `.hashes.sha256`
- `.hashes.md5`
- `.imphash.imphash`
- `.behavior.behaviors[]`
- `.iocs.urls[]`
- `.iocs.domains[]`
- `.iocs.registry_keys[]`
- `.iocs.file_paths[]`
- `.sections[]`

Example extraction:

```bash
jq '{
  sha256: .hashes.sha256,
  imphash: .imphash.imphash,
  rules: [.behavior.behaviors[].rule],
  urls: [.iocs.urls[]?],
  domains: [.iocs.domains[]?]
}' sample_analysis.json
```

## Packed Binaries

Packed malware often produces weak static results. Common signs:

- Entropy above `7.0`
- Very small import table
- Heavy use of `LoadLibrary` and `GetProcAddress`
- Few useful strings

Recommended response:

1. Record the packing indicators.
2. Let BAT auto-unpack UPX when possible.
3. Re-run analysis on the unpacked file if you can.
4. Use sandbox or detonation analysis when packing remains opaque.

Do not downgrade risk purely because static output is sparse on a packed sample.

## Decompilation Notes

Use decompilation when basic triage suggests the sample is worth deeper review.

- `r2`: faster, lighter native pseudocode
- `ghidra`: richer output with suspicious-function filtering
- `both`: useful when you want another view of the same sample

The Ghidra filter keeps functions that score on suspicious APIs, relevant keywords, URLs, paths, and overall size. The goal is to show likely logic, not every helper function.

## Common False Positives

Some findings need context:

- Installers and updaters may create processes, write registry keys, or download files
- Security tools and admin utilities may enumerate the system or use low-level APIs
- Packed commercial software can look suspicious even when benign
- Crypto APIs alone are usually informational

Escalate based on combinations, not isolated medium-signal findings.

## Known Limitations

- Packed or encrypted samples can hide the real payload.
- Custom loaders may expose few useful imports or strings.
- Static analysis cannot confirm whether a capability actually executed.
- Benign admin tools, installers, and security software can resemble malware in parts of their behavior.
- A weak verdict does not clear a suspicious sample when context is poor.

## What BAT Does Not Prove

BAT does not prove:

- The sample ran on the host
- The attacker achieved persistence
- Data was successfully exfiltrated
- A specific malware family or actor is responsible
- The sample is safe because the verdict is weak

Use endpoint, network, and identity telemetry to confirm real-world impact.

## Working with IOCs

The JSON report is the easiest format for automation. Use it to:

- Push domains and URLs into detections
- Search endpoints for paths and registry keys
- Revoke exposed tokens
- Correlate artifacts across cases

Minimal SOC/CERT workflow:

1. Promote domains, URLs, and hashes into detection or block workflows.
2. Search endpoints for registry keys, paths, mutexes, and dropped filenames.
3. Revoke exposed credentials and tokens.
4. Tie the artifacts back to the alert, user, host, and delivery vector.
5. Document whether you found execution, persistence, or lateral spread.

If exfiltration or credential-theft rules fired and the sample executed, respond as though the exposed data was compromised.

## Remediation Checklist

For a confirmed malicious sample:

1. Isolate affected hosts.
2. Quarantine the binary and preserve a copy for analysis.
3. Block extracted domains, URLs, and known hashes where appropriate.
4. Hunt for the same IOCs across endpoints, email, DNS, proxy, and EDR data.
5. Remove persistence artifacts.
6. Revoke exposed credentials, sessions, tokens, and API keys.
7. Review whether outbound traffic indicates exfiltration or payload download.
8. Decide whether reimage, password reset, or broader containment is required.

## Suggested Analyst Routine

1. Run BAT.
2. Read the verdict.
3. Check hashes and imphash.
4. Review IOCs.
5. Read the highest-severity behavioral rules.
6. Check entropy and packing signals.
7. Escalate to sandboxing or deeper reverse engineering only when justified.

## Escalation Triggers

Escalate immediately when BAT shows any of the following:

- Process injection, hollowing, reflective DLL loading, or shellcode execution
- Credential theft targeting browsers, wallets, password managers, or messaging apps
- Discord webhook, Telegram bot, or file-upload exfiltration
- Shadow copy deletion, ransom-note text, mass deletion, MBR access, or format commands
- Driver loading, physical memory access, or other rootkit indicators
- High entropy plus sparse imports on a suspicious or user-delivered sample

## Glossary

- `imphash`: a hash of imported functions used to cluster related binaries.
- `Entropy`: a rough measure of randomness; high entropy often suggests packing or encryption.
- `Overlay`: data appended after the normal PE structure; often used to hide payloads or config.
- `TLS callback`: code that runs before the program's normal entry point.
- `capa`: a capability analysis tool that identifies what a binary can do, independent of signatures.
