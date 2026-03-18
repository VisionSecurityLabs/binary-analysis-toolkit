# Binary Analysis Toolkit -- Analyst Guide

This guide is written for CERT and SOC analysts who need to triage suspicious Windows executables quickly and accurately. It assumes you know what a PE file is and have basic familiarity with Windows, but does not assume expertise in reverse engineering or malware analysis.

This is a companion to the project README. Where the README covers installation and architecture, this guide covers **what to do** with the tool's output and how to fold it into your incident response workflow.

---

## Table of Contents

1. [Triage Workflow](#1-triage-workflow)
2. [Reading the Behavioral Rules](#2-reading-the-behavioral-rules)
3. [Understanding Entropy](#3-understanding-entropy)
4. [Ghidra Intelligent Filtering](#4-ghidra-intelligent-filtering)
5. [capa vs. Behavioral Rules](#5-capa-vs-behavioral-rules)
6. [Working with IOCs](#6-working-with-iocs)
7. [Dealing with Packed Binaries](#7-dealing-with-packed-binaries)
8. [.NET Binary Analysis](#8-net-binary-analysis)
9. [Common False Positives](#9-common-false-positives)
10. [Integration with Other Tools](#10-integration-with-other-tools)

---

## 1. Triage Workflow

When a suspicious PE file arrives -- from an email attachment, an endpoint alert, a phishing lure, or a file share scan -- follow this step-by-step process. Each step builds on the previous one and tells you whether to escalate or close.

### Step 1: Run the basic analysis

```bash
uv run binanalysis sample.exe
```

JSON and HTML reports are automatically saved as `sample_analysis.json` and `sample_analysis.html` next to the binary. You will use these later for SIEM ingestion and sharing with your team.

The terminal output is designed to be read top-to-bottom. Skim it once, then focus on the sections described below.

### Step 2: Check the verdict

Scroll to the bottom of the output. The **CLASSIFICATION** section gives you a one-line verdict:

| Verdict | What it means | Your next action |
|---------|---------------|------------------|
| **MALICIOUS** | At least one critical-severity rule fired. The binary almost certainly has offensive capability. | Escalate immediately. Quarantine the file. If it was found running on a system, begin incident response. |
| **LIKELY MALICIOUS** | Two or more high-severity rules fired, or a combination of high-severity rules and offensive capa capabilities. | Treat as high priority. Cross-reference hashes on VirusTotal. Check whether anyone in your organization expected this file. |
| **SUSPICIOUS** | Medium-severity indicators are present. The binary does things that could be legitimate but are also consistent with malware. | Investigate in context. Who sent it? Where was it found? Does the behavior match the file's claimed purpose? |
| **No strong indicators** | No rules fired above medium severity. | This does NOT mean the file is safe. If the binary has high-entropy sections and few imports, it is likely packed -- and the verdict is telling you that static analysis cannot see through the packing. Proceed to dynamic analysis. |

### Step 3: Look at hashes -- search VirusTotal

The first section of the output lists MD5, SHA1, and SHA256 hashes.

1. Copy the **SHA256** hash.
2. Go to [VirusTotal](https://www.virustotal.com) and paste it in the search bar.
3. If the sample has been seen before, you get instant context: detection names, first-seen dates, behavioral reports from sandboxes, community comments.

If VirusTotal has no results, the sample may be new or targeted. This is itself a finding worth noting in your ticket.

Also copy the **imphash** (import hash). Two files with the same imphash share the same imported function table, which usually means they were built by the same developer or malware builder. Search the imphash on VirusTotal (use `imphash:<value>` in the search bar) to find related samples.

### Step 4: Review IOCs -- feed into SIEM/SOAR

The **INDICATORS OF COMPROMISE** section lists extracted URLs, domains, embedded credentials, file paths, registry keys, and more. These are your actionable outputs:

- **URLs and domains**: Block at the proxy/firewall. Add to watchlists. Search historical DNS and proxy logs.
- **Embedded credentials or tokens**: If you find a GitHub PAT, Bearer token, or API key, treat it as compromised. Revoke it. Notify the token owner.
- **Registry keys**: Search your EDR for these keys across your fleet. If other endpoints have them, they may be compromised too.
- **File paths**: Same as registry keys -- search across endpoints.

The JSON report (`sample_analysis.json`) contains all IOCs in structured form. See Section 10 for how to ingest this into Splunk, Elastic, and other platforms.

### Step 5: Examine behavioral rules -- understand capabilities

The **BEHAVIORAL ANALYSIS** section lists every rule that fired, grouped by category. Read the descriptions -- they are written in plain English and tell you what the binary *can do*:

- "Classic process injection (VirtualAllocEx -> WriteProcessMemory -> CreateRemoteThread)" tells you the binary can inject code into other running processes.
- "Targets browser credential databases (Login Data, cookies, Web Data)" tells you the binary is an infostealer.
- "Deletes Volume Shadow Copies (vssadmin / wmic shadowcopy delete)" tells you the binary is likely ransomware.

Use the category names (injection, credential_theft, impact, persistence, etc.) to map findings to your incident response playbook. Section 2 of this guide explains every category in detail.

### Step 6: Assess packing and obfuscation

Check the **SECTIONS** table for entropy values. If any section has entropy above 7.0, the binary is almost certainly packed or encrypted. This means:

- The behavioral rules may have missed things because the real code is hidden.
- The strings that were extracted are likely from the unpacker stub, not the payload.
- You should run the sample in a sandbox (ANY.RUN, Joe Sandbox, etc.) to see what it does when it actually runs.

See Section 7 for detailed guidance on packed binaries.

### Step 7: Go deeper if needed

If the triage results warrant deeper investigation:

```bash
# Decompile with Ghidra (filtered to suspicious functions only)
uv run binanalysis sample.exe --decompile ghidra

# Or use both Radare2 and Ghidra
uv run binanalysis sample.exe --decompile both
```

The Ghidra integration does not dump all functions. It scores every function against the suspicious indicators already found in the binary and shows only the ones that matter, organized by attack category. See Section 4 for details.

---

## 2. Reading the Behavioral Rules

The analyzer includes 98 generic behavioral rules. Each rule combines multiple signals -- imports, strings, section characteristics, and string-pattern findings -- to detect a specific technique. A rule firing means the binary has the *static indicators* of that technique, not that it necessarily executes it (that requires dynamic analysis to confirm).

Rules are grouped by MITRE ATT&CK-aligned categories. Here is what each group means, why it matters, and what you should do when rules in that group trigger.

### Injection (7 rules)

**What it means in plain language:** The binary can insert its own code into another running process. This is one of the most common and dangerous malware techniques. After injection, the malicious code runs inside a legitimate process (like `explorer.exe` or `svchost.exe`), making it harder for security tools to detect.

**Rules in this group:**
- `process_injection` -- Classic injection chain: allocate memory in another process, write code into it, start a thread to execute it.
- `apc_injection` -- Abuses the Windows APC (Asynchronous Procedure Call) mechanism to run code in another process's thread.
- `dll_injection` -- Forces another process to load a malicious DLL.
- `hook_injection` -- Uses Windows hooks (like keyboard or mouse hooks) to get code loaded into other processes.
- `ntcreatethread` -- Uses low-level NT functions to create threads in remote processes, bypassing some security tools.
- `process_hollowing` (Critical) -- Creates a legitimate process in a suspended state, hollows out its memory, replaces it with malicious code, then resumes it. The malicious code runs under the identity of the legitimate process.
- `reflective_dll_injection` (Critical) -- Loads a DLL entirely from memory without ever touching disk, bypassing most file-based security tools.

**Why it matters:** Injection is almost never used by legitimate software. If you see injection rules firing, the binary is almost certainly offensive.

**What to do:** Escalate. If this binary ran on a system, check what processes it may have injected into. Look at process trees and parent-child relationships in your EDR. The injected process will appear legitimate in task manager, so you need EDR telemetry to identify the injection.

### Defense Evasion / Anti-Analysis (9 rules)

**What it means:** The binary actively tries to avoid detection and analysis. It may check if it is running in a debugger, a virtual machine, or a sandbox. It may use techniques to bypass endpoint detection and response (EDR) tools.

**Rules in this group:**
- `anti_debug_api` -- Checks for debugger presence using standard Windows APIs.
- `anti_debug_nt` -- Uses the lower-level `NtQueryInformationProcess` function to detect debuggers, which is harder for security tools to hook.
- `timing_evasion` -- Uses timing functions (`GetTickCount`, `QueryPerformanceCounter`) together, likely to detect if execution is being slowed by a debugger or sandbox.
- `anti_vm` -- Contains strings associated with VMware, VirtualBox, QEMU, Sandboxie, or Cuckoo sandbox.
- `tls_callback` -- Has TLS (Thread Local Storage) callbacks that execute code before the program's main entry point. This can run anti-analysis checks before a debugger even attaches.
- `rwx_section` -- Has a PE section that is both writable and executable. Legitimate software rarely needs this; malware uses it to write shellcode and run it in the same memory.
- `high_entropy_section` -- A section with entropy above 7.0, indicating it is packed or encrypted.
- `no_import_table` -- The binary has no import table at all, meaning it resolves all Windows API calls at runtime to hide its true capabilities.
- `direct_syscalls` -- Uses NT system calls directly (`NtAllocateVirtualMemory`, `NtProtectVirtualMemory`, etc.), bypassing user-mode hooks that EDR products rely on.

**Why it matters:** Legitimate software has no reason to detect debuggers or virtual machines (with rare exceptions like some DRM and anti-cheat systems). Direct syscalls specifically indicate an attacker who is aware of and actively trying to bypass your endpoint security.

**What to do:** If `direct_syscalls` fires, note this in your ticket -- it means the attacker is sophisticated and your EDR may not have full visibility. If `anti_vm` fires and your sandbox analysis was clean, the malware may have detected the sandbox and refused to execute its payload. Try a different sandbox or use a bare-metal analysis environment.

### Credential Access (13 rules)

**What it means:** The binary steals credentials, passwords, tokens, or sensitive data from the system it runs on.

**Rules in this group:**
- `credential_api` -- Uses Windows APIs for credential enumeration and DPAPI decryption (the system used to protect saved passwords).
- `browser_credential_theft` (Critical) -- Targets browser databases where passwords, cookies, and autofill data are stored (Chrome's `Login Data`, Firefox's `logins.json`, etc.).
- `browser_path_access` -- References the file paths where Chrome, Firefox, Edge, Brave, or Opera store their profiles.
- `browser_masterkey` (Critical) -- Specifically targets the browser's master encryption key (`encrypted_key` from the `Local State` file), which is needed to decrypt all saved passwords.
- `crypto_wallet_theft` (Critical) -- Targets cryptocurrency wallet files (Electrum, Exodus, MetaMask, Atomic, Coinomi, Phantom, etc.).
- `discord_token_theft` -- Targets Discord's token storage to hijack accounts.
- `telegram_data_theft` -- Targets Telegram Desktop's session data (`tdata` directory).
- `ftp_ssh_credential_theft` -- Targets saved credentials in FileZilla, WinSCP, or PuTTY.
- `email_client_theft` -- Targets Outlook or Thunderbird data.
- `password_manager_targeting` (Critical) -- Targets password manager databases (KeePass, LastPass, Bitwarden, 1Password, Dashlane).
- `vpn_credential_theft` -- Targets VPN credentials (NordVPN, OpenVPN, ProtonVPN).
- `gaming_data_theft` -- Targets Steam or Minecraft account data.
- `keylogger` (Critical) -- Uses keyboard state APIs (`GetAsyncKeyState`, `GetKeyboardState`) to record keystrokes.

**Why it matters:** Credential theft is the primary objective of infostealers, one of the most common malware categories. Stolen credentials lead to account takeover, lateral movement, data exfiltration, and financial fraud.

**What to do:** If credential theft rules fire and the binary ran on a system:
1. Assume all credentials stored on that system are compromised.
2. Force password resets for the affected user.
3. Revoke all active sessions (browser, VPN, email).
4. If `crypto_wallet_theft` fired, warn the user that cryptocurrency may have been transferred.
5. If `browser_masterkey` fired, all saved browser passwords for all profiles on that machine should be considered compromised.
6. Check for data exfiltration -- see the exfiltration rules below.

### Privilege Escalation (2 rules)

**What it means:** The binary attempts to gain higher privileges on the system than it currently has.

**Rules:**
- `token_manipulation` -- Opens a process token and adjusts its privileges (e.g., enabling `SeDebugPrivilege` to access other processes' memory).
- `token_impersonation` -- Duplicates or impersonates another user's security token to act as that user.

**Why it matters:** Privilege escalation allows malware to disable security software, access protected files, and perform actions that require administrator rights.

**What to do:** Check whether the binary ran with elevated privileges. If it did, the scope of potential damage is larger. Look for evidence of security software being disabled or tampered with.

### Persistence (5 rules)

**What it means:** The binary installs itself to survive reboots. After the system restarts, the malware will run again automatically.

**Rules:**
- `registry_autorun` -- Writes to the `Run` or `RunOnce` registry keys, which Windows checks at every logon.
- `service_creation` -- Creates a Windows service, which runs in the background automatically.
- `scheduled_task` -- Creates a scheduled task using `schtasks` or the Task Scheduler COM interface.
- `startup_folder` -- Places files in the user's Startup folder.
- `driver_loading` (Critical) -- Loads a kernel driver, which is the deepest form of persistence and runs with the highest system privileges.

**Why it matters:** Persistence means the infection will continue even after a reboot. Removing the binary from disk is not enough -- you must also remove the persistence mechanism.

**What to do:** Check the extracted registry keys and file paths in the IOC section. Search your fleet for those specific persistence artifacts. When remediating, delete both the binary AND the persistence mechanism (registry key, service, scheduled task, or startup entry).

### Execution (5 rules)

**What it means:** The binary creates child processes or launches other programs.

**Rules:**
- `process_creation` -- Uses `CreateProcess` or `WinExec` to start new processes.
- `shellexecute` -- Uses `ShellExecute` to launch programs (can also open URLs or documents).
- `dynamic_api_resolution` -- Resolves Windows APIs at runtime using `GetProcAddress` and `LoadLibrary`, hiding its true capabilities from the import table.
- `powershell_execution` -- References `powershell.exe` or `pwsh.exe`.
- `recon_commands` -- Contains reconnaissance command strings like `whoami`, `systeminfo`, `ipconfig`, `hostname`, or `tasklist`.

**Why it matters:** Process creation is how malware executes additional payloads, runs commands, and performs actions on the system. PowerShell execution is especially concerning because PowerShell can download and run arbitrary code from the internet.

**What to do:** If `powershell_execution` fires, look for encoded PowerShell commands in the strings. Check your endpoint logs for PowerShell execution with `-enc` or `-EncodedCommand` flags. If `recon_commands` fires, the binary is gathering information about the system, which is typical of the early stages of an attack.

### Network / Command and Control (7 rules)

**What it means:** The binary communicates over the network, potentially with an attacker-controlled server.

**Rules:**
- `winhttp_usage` -- Uses the WinHTTP library for HTTP requests.
- `wininet_usage` -- Uses the WinINet library for HTTP requests.
- `url_download` -- Uses `URLDownloadToFile` to download files from the internet directly to disk.
- `raw_sockets` -- Uses raw sockets (`WSAStartup` + `connect`) for network communication.
- `embedded_urls` -- Contains embedded URLs found in the binary's strings.
- `named_pipe_c2` -- Uses named pipes for inter-process communication, which can serve as a local C2 channel or lateral movement mechanism.
- `proxy_tunnel` -- Contains SOCKS proxy or tunnel references, indicating the ability to route traffic through intermediate servers.

**Why it matters:** Network communication is how malware receives commands, downloads additional payloads, and exfiltrates stolen data. The URLs and domains extracted as IOCs are your most actionable network indicators.

**What to do:** Check the extracted URLs and domains. Block them at your firewall/proxy. Search your DNS and proxy logs for any hosts that have contacted these destinations. If `url_download` fires, check for recently downloaded files in Temp directories on affected systems.

### Exfiltration (3 rules)

**What it means:** The binary sends stolen data out of your network.

**Rules:**
- `discord_webhook_exfil` (Critical) -- Uses a Discord webhook URL to send data. This is extremely common in commodity infostealers because Discord webhooks are free, anonymous, and hard to block without blocking all of Discord.
- `telegram_bot_exfil` (Critical) -- Uses the Telegram Bot API to send data. Similar to Discord webhooks in popularity among malware authors.
- `file_upload_exfil` -- Uses HTTP multipart file upload, indicating it packages and sends files to a remote server.

**Why it matters:** Exfiltration is the attacker's goal. If these rules fire, data has likely already left your network (assuming the binary ran).

**What to do:** If you find a Discord webhook URL in the IOCs, report it to Discord for takedown (use the Trust & Safety reporting form). Check your proxy logs for outbound connections to `discord.com/api/webhooks` or `api.telegram.org`. The specific webhook URL or bot token in the IOCs can help you understand what data was exfiltrated.

### Impact (14 rules)

**What it means:** The binary causes damage -- encrypting files (ransomware), deleting data (wiper), mining cryptocurrency (cryptominer), or destroying the system.

**Ransomware rules:**
- `shadow_copy_deletion` (Critical) -- Deletes Volume Shadow Copies, which are Windows' built-in backup snapshots. This is done to prevent file recovery.
- `disable_recovery` (Critical) -- Disables Windows recovery options via `bcdedit`.
- `delete_backup_catalog` -- Deletes the Windows backup catalog via `wbadmin`.
- `ransom_note` (Critical) -- Contains ransom note text like "Your files have been encrypted."
- `ransom_payment` (Critical) -- References cryptocurrency payment addresses (Bitcoin, Monero).
- `ransom_extension` -- References file extensions associated with ransomware (`.encrypted`, `.locked`, `.crypt`).
- `bulk_file_encryption` (Critical) -- Combines file enumeration APIs with encryption APIs, the core ransomware loop.
- `drive_enumeration` -- Enumerates logical drives, which ransomware does to find all volumes to encrypt.
- `safemode_boot` -- Configures safe mode boot, a technique used by ransomware to bypass security software that does not load in safe mode.

**Wiper/destructive rules:**
- `mbr_overwrite` (Critical) -- References the Master Boot Record and physical drive access together, indicating a wiper or bootkit.
- `physical_drive_access` (Critical) -- Accesses `\\.\PhysicalDrive0` directly, bypassing the filesystem.
- `forced_shutdown` -- Forces a system shutdown or reboot.
- `mass_file_deletion` (Critical) -- Contains mass deletion commands (`del /s /f`, `rmdir /s`, `Remove-Item -Recurse`).
- `secure_overwrite` (Critical) -- References secure file overwrite tools (`cipher /w`, `SDelete`), making data recovery impossible.
- `format_drive` (Critical) -- Contains drive format commands.

**Cryptominer rules:**
- `crypto_miner` (Critical) -- Contains mining software names (xmrig, cpuminer), Stratum protocol URLs, or mining pool domain names.
- `mining_algorithm` -- References specific mining algorithms (CryptoNight, RandomX, Ethash).
- `miner_cli_args` -- Contains mining software command-line arguments (`--donate-level`, `--threads`, `--algo`).
- `monero_wallet` -- Contains a Monero wallet address.

**Why it matters:** Impact is the end goal of destructive attacks. Ransomware and wipers can cause catastrophic damage. Cryptominers degrade system performance and indicate unauthorized access.

**What to do for ransomware:** If ransomware indicators fire and the binary has not yet executed, you have prevented the attack. Quarantine the file and notify the team. If it has already executed, isolate the affected system immediately. Do NOT pay the ransom without involving management, legal, and potentially law enforcement. Check the [No More Ransom](https://www.nomoreransom.org/) project for free decryption tools.

**What to do for wipers:** Isolate the system immediately. If `mbr_overwrite` or `physical_drive_access` fired and the binary ran, the system may be unrecoverable. Focus on containment to prevent spread.

**What to do for cryptominers:** Lower priority than ransomware but still indicates a compromise. The attacker who deployed the miner likely has broader access. Investigate how the miner was delivered.

### Collection (4 rules)

**What it means:** The binary gathers information from the system -- screenshots, clipboard contents, webcam, or audio.

**Rules:**
- `screenshot_capture` -- Uses Windows GDI functions (`BitBlt`, `GetDesktopWindow`) to capture the screen.
- `clipboard_theft` -- Monitors or reads the clipboard (where copied passwords, URLs, and cryptocurrency addresses may be found).
- `webcam_capture` -- Uses webcam capture APIs.
- `audio_recording` -- Uses audio recording APIs.

**Why it matters:** Collection capabilities are typical of RATs (Remote Access Trojans) and surveillance malware. Webcam and audio recording are particularly invasive.

**What to do:** If these rules fire alongside C2 or network rules, the binary is likely a RAT. If `clipboard_theft` fires alongside cryptocurrency wallet theft rules, the malware may be a clipboard hijacker that replaces cryptocurrency addresses with the attacker's address.

### Lateral Movement (5 rules)

**What it means:** The binary tries to spread to other systems on the network.

**Rules:**
- `usb_propagation` -- Creates `autorun.inf` files or uses `GetDriveType` to detect removable media, indicating it spreads via USB drives.
- `network_share_propagation` -- Accesses administrative shares (`ADMIN$`, `IPC$`) or uses `net share` commands to spread to other network systems.
- `network_enumeration` -- Enumerates network shares or servers to discover targets.
- `unc_path_access` -- Accesses UNC paths (`\\IP\share`), indicating network file access.
- `email_worm` -- Contains SMTP commands (`MAIL FROM`, `RCPT TO`), indicating it spreads via email.

**Why it matters:** Lateral movement turns a single compromised endpoint into a network-wide incident.

**What to do:** If lateral movement rules fire, immediately check for the same binary (by hash) or the same IOCs on other systems. Monitor network traffic for SMB connections from the affected system. If `email_worm` fires, check your mail gateway logs for outbound messages from the affected user.

### RAT / Backdoor (4 rules)

**What it means:** The binary provides remote access and control to an attacker.

**Rules:**
- `reverse_shell` (Critical) -- Combines shell command references (cmd.exe) with network or pipe communication, indicating a reverse shell.
- `remote_desktop_access` -- References RDP or VNC protocols.
- `file_manager_capability` -- Provides remote file browsing and transfer.
- `remote_input` -- Simulates keyboard and mouse input remotely.

**Why it matters:** A RAT gives the attacker full interactive control of the system, equivalent to sitting at the keyboard.

**What to do:** Escalate immediately. If the binary ran, the attacker may have had real-time control. Check your EDR for interactive logon events and unusual process execution patterns.

### Masquerading (1 rule)

**What it means:** The binary claims to be from a well-known vendor (Microsoft, Adobe, Google, Mozilla, Apple) in its version info, but its actual characteristics do not match -- for example, it has no import table or has high-entropy sections.

**Rules:**
- `version_mismatch` -- Version info claims a known vendor but the binary lacks expected characteristics.

**Why it matters:** Masquerading is used to make malware appear legitimate in file explorer, task manager, and security tool logs.

**What to do:** Check the version info in the report. Compare it to the actual file's behavior. A file claiming to be "Microsoft Excel" that imports injection APIs is clearly malicious.

### Loader / Dropper (3 rules)

**What it means:** The binary's primary purpose is to deliver and execute another payload.

**Rules:**
- `drops_to_temp` -- Drops executable files to Temp or AppData directories.
- `embedded_pe` -- Contains an embedded PE file (a second executable hidden inside the first).
- `shellcode_execution` (Critical) -- Uses `VirtualAlloc` + `VirtualProtect` without remote thread creation, indicating it allocates memory, writes shellcode, marks it executable, and runs it locally.

**Why it matters:** Loaders are the first stage of a multi-stage attack. The real payload may be significantly more dangerous than the loader itself.

**What to do:** If `embedded_pe` fires, the second-stage payload may be in the binary's resources or overlay. Check the overlay analysis section for embedded PE files. If `drops_to_temp` fires, check the Temp and AppData directories on affected systems for dropped files.

### Rootkit (5 rules)

**What it means:** The binary operates at the deepest levels of the operating system -- loading kernel drivers, hooking system service tables, or accessing physical memory directly.

**Rules:**
- `driver_loading` (Critical) -- Loads a kernel driver using `NtLoadDriver` or `ZwLoadDriver`.
- `ssdt_hook` (Critical) -- References the System Service Descriptor Table, which is hooked to intercept system calls.
- `physical_drive_access` (Critical) -- Accesses physical drives directly, bypassing the filesystem.
- `physical_memory_access` (Critical) -- Accesses physical memory directly.
- `driver_path_reference` -- References driver directories or driver registry keys.

**Why it matters:** Rootkits are the most difficult malware to detect and remove. They can hide files, processes, and network connections from the operating system itself.

**What to do:** If rootkit rules fire, this is a critical escalation. Standard remediation tools may not be effective. Consider reimaging the affected system rather than attempting to clean it.

### Banking Trojan (5 rules)

**What it means:** The binary intercepts or modifies web traffic to steal banking credentials or redirect financial transactions.

**Rules:**
- `web_inject` (Critical) -- Injects HTML or JavaScript into web pages viewed by the user (man-in-the-browser attack).
- `webinject_config` (Critical) -- Contains web inject configuration directives (`set_url`, `data_before`, `data_inject`).
- `banking_target` -- References banking or financial institution names.
- `certificate_install` -- Installs certificates to intercept encrypted HTTPS traffic (man-in-the-middle).
- `http_hook` -- Hooks HTTP request functions to intercept web traffic.

**Why it matters:** Banking trojans directly target financial transactions. They can modify what the user sees on their banking website, redirect payments, or steal credentials during login.

**What to do:** If banking trojan rules fire, immediately freeze any financial accounts accessed from the affected system. Review recent transactions. Notify the user's bank. Check whether the certificate store on the affected system has any unauthorized root certificates.

### Cryptography (3 rules)

**Rules:**
- `crypto_encrypt` -- Uses Windows Crypto API encryption functions.
- `crypto_decrypt` -- Uses Windows Crypto API decryption functions.
- `base64_encoding` -- Uses Base64 encoding via the Windows API.

**Why it matters:** Cryptography rules are low-severity and mostly informational. Many legitimate programs use encryption. These rules become significant when combined with other indicators -- for example, encryption APIs plus file enumeration APIs strongly suggest ransomware (covered by the `bulk_file_encryption` rule).

**What to do:** Do not escalate based on crypto rules alone. Use them as context when interpreting other findings.

### Discovery (3 rules)

**Rules:**
- `recon_commands` -- Contains reconnaissance command strings (`whoami`, `systeminfo`, `ipconfig`, `hostname`, `tasklist`).
- `drive_enumeration` -- Enumerates logical drives.
- `network_enumeration` -- Enumerates network shares and servers.

**Why it matters:** Discovery is the attacker's reconnaissance phase. They are mapping the environment before taking further action.

**What to do:** If discovery rules fire alongside C2 or persistence rules, the binary is likely part of an active intrusion. Check whether these reconnaissance commands actually executed by reviewing endpoint command-line logging.

---

## 3. Understanding Entropy

Entropy is a measure of randomness in data. The analyzer computes Shannon entropy for every PE section, and this number tells you a lot about what the section contains.

### The entropy scale

| Entropy | What it typically means | Example |
|---------|------------------------|---------|
| 0.0 | All bytes are identical | A section full of null bytes (padding) |
| ~1.0-2.0 | Very repetitive data | Simple data tables, sparse arrays |
| ~4.0-5.0 | Human-readable text | English text, configuration files, error messages |
| ~5.0-6.0 | Compiled code | Normal executable code (.text sections) |
| ~6.0-6.5 | Compressed resources | PNG images, zlib-compressed data, compiled resources |
| ~6.5-7.0 | Elevated -- possibly compressed or obfuscated | May be benign (complex resources) or suspicious (light obfuscation) |
| 7.0-7.9 | Almost certainly packed or encrypted | Compressed executables (UPX, Themida, VMProtect) or encrypted payloads |
| ~8.0 | Maximum theoretical randomness | Truly random data or strong encryption output |

### Why entropy matters for triage

Normal compiled executables have a `.text` (code) section with entropy around 5.5-6.5 and a `.data` section with entropy around 3.0-5.0. When you see a section with entropy above 7.0, it means the data in that section is nearly random, which strongly suggests one of two things:

1. **The binary is packed.** A packer compresses or encrypts the real executable and bundles it with a small unpacker stub. When the program runs, the stub decompresses the real code in memory and jumps to it. Packers are used by both legitimate software (for size reduction) and malware (to evade signature-based detection).

2. **The section contains encrypted data.** This could be an encrypted configuration file, an encrypted second-stage payload, or encrypted strings that are decrypted at runtime.

### How packed malware uses entropy to hide

When a binary is packed:

- The `.text` section (code) will have entropy around 7.0-7.9 instead of the normal 5.5-6.5.
- The import table will be very small, often containing only `LoadLibraryA`, `GetProcAddress`, and `VirtualAlloc` -- just enough for the unpacker to work.
- Most strings will be from the unpacker stub, not the actual malware.
- Most behavioral rules will not fire because the real imports and strings are hidden inside the encrypted data.

This is why a "No strong indicators" verdict on a binary with high-entropy sections is actually a significant finding -- it means the binary is hiding something.

### What to do about high entropy

If you see high-entropy sections:

1. Note the finding in your ticket.
2. Check if YARA packer detection rules identified the packer (e.g., UPX, Themida, VMProtect).
3. If the packer is known, consider unpacking it statically (e.g., `upx -d` for UPX-packed binaries) and re-running the analysis.
4. If the packer is unknown or custom, submit the sample to a sandbox for dynamic analysis. The sandbox will observe the binary after it unpacks itself.
5. Run capa analysis -- capa can sometimes detect capabilities even in packed binaries by looking at instruction-level patterns in the unpacker stub.

---

## 4. Ghidra Intelligent Filtering

When you run the analyzer with `--decompile ghidra`, it does not simply dump all decompiled functions. A typical binary has hundreds or thousands of functions, and most of them are uninteresting boilerplate (C runtime initialization, error handling, memory management). Reading all of them would be impractical.

Instead, the analyzer applies an intelligent filtering system that shows you only the functions that matter.

### How the filtering works

After Ghidra decompiles all functions, each one is scored based on five factors:

1. **Suspicious API calls** (highest weight, 3 points each): If the function calls any API from the analyzer's suspicious import list (~138 APIs across 17 categories), it gets 3 points per API. These are APIs associated with injection, credential theft, evasion, network communication, etc.

2. **Context-derived keyword matches** (1 point each): Keywords are dynamically extracted from the analyzer's own findings -- URLs, domains, file paths, registry keys, dynamic API names, and other strings the binary contains. This is what makes the filter adaptive. If the binary contains Discord webhook URLs, the filter will look for those URLs in the decompiled code.

3. **Embedded URLs** (2 points each): URLs found in the function's decompiled code.

4. **Windows file paths** (1 point each): Windows paths found in the function's code.

5. **Function size** (1 point bonus): Functions with more than 50 lines get a bonus point, since larger functions are more likely to contain real logic.

Functions scoring 3 or higher are kept. Everything else is discarded.

### Attack categories

Each interesting function is assigned to one of approximately 25 attack categories based on the indicators it matched:

- Ransomware
- Ransomware Encryption Loop
- Wiper / Destructive
- Rootkit / Driver
- Crypto Miner
- Banking Trojan
- Worm / Propagation
- RAT / Backdoor
- RAT / Reverse Shell
- Process Injection
- Browser Data Theft
- Crypto Wallet Theft
- Messaging App Theft
- FTP/SSH Credential Theft
- Email Data Theft
- Password Manager Theft
- Gaming Data Theft
- Keylogging
- Screen Capture
- Clipboard Theft
- Data Exfiltration
- Network / C2
- Credential Access
- Cryptography
- Persistence
- Evasion / Anti-Analysis
- Reconnaissance
- Execution
- Suspicious (catch-all)

### Why the filter is adaptive

The key design principle is that keywords are not hardcoded to any specific malware family. They are derived from whatever the analyzer already found in the binary during its earlier analysis phases:

- If the string analysis found `api.github.com` and `encrypted_key`, those become search terms in the decompiled code.
- If the dynamic API detection found `NtAllocateVirtualMemory`, that becomes a search term.
- If the import analysis found unusual DLLs, their names become search terms.

This means the filter works equally well on an infostealer targeting Discord, a ransomware variant using custom encryption, or a RAT communicating via named pipes. It adapts to whatever the binary actually does.

### Reading the output

The filtered output is saved to `<filename>_ghidra_analysis.c` next to the binary. It is organized by attack category, with the highest-scoring categories first:

```
// CATEGORY: Browser Data Theft
// ── FUN_004012a0 @ 004012a0 ──
// Score: 12 | Triggers: API: CryptUnprotectData, keyword: Login Data, keyword: encrypted_key
<decompiled C code>

// CATEGORY: Network / C2
// ── FUN_00401580 @ 00401580 ──
// Score: 8 | Triggers: keyword: https://discord.com/api/webhooks, API: InternetOpenA
<decompiled C code>
```

**What to do:** Focus on the highest-scored functions first. Read the trigger list to understand why each function was flagged. The decompiled code will show you the actual implementation -- how the malware accesses browser databases, constructs HTTP requests, or performs injection.

---

## 5. capa vs. Behavioral Rules

The analyzer has two complementary detection systems. Understanding the difference helps you interpret their results correctly.

### Behavioral rules (built-in)

The 98 behavioral rules work by pattern matching against three data sources:

- **Imported function names** -- What Windows APIs does the binary declare it uses?
- **Extracted strings** -- What text, URLs, file paths, and patterns are embedded in the binary?
- **Section characteristics** -- Do any sections have unusual permissions or entropy?

Behavioral rules are fast (they run in milliseconds) and configurable (you can add new rules easily). But they are surface-level: they can only see what the binary openly declares in its import table and string data. If a binary dynamically resolves APIs at runtime or encrypts its strings, the behavioral rules will miss those capabilities.

### capa (optional integration)

capa is an open-source tool by Mandiant's FLARE team. It works differently: it analyzes the binary's actual machine code instructions, looking for patterns that implement specific capabilities. For example, capa can detect that a binary implements HTTP communication by recognizing the sequence of function calls and data structures used, even if the API names are not in the import table.

capa uses a large rule set (thousands of rules) maintained by the security research community, and maps its findings to MITRE ATT&CK techniques.

### How they complement each other

| Scenario | Behavioral rules | capa |
|----------|-----------------|------|
| Binary with clear imports and strings | Catches most capabilities | Also catches them, plus deeper details |
| Binary with dynamic API resolution | Misses hidden APIs (may catch some via dynamic API detection) | May still detect capabilities via code patterns |
| Packed binary | Misses most capabilities (only sees unpacker stub) | May detect some capabilities in the unpacker stub |
| .NET binary | Works well (rich metadata) | Limited support for .NET |
| Quick triage (speed matters) | Runs in milliseconds | Takes 10-60 seconds depending on binary size |

### What to do in practice

For initial triage, the behavioral rules are sufficient. If the behavioral rules produce a MALICIOUS or LIKELY MALICIOUS verdict, you have enough to escalate.

Enable capa (by not passing `--no-capa`) when:
- The behavioral rules give "No strong indicators" but the binary is suspicious for other reasons.
- You need to confirm specific capabilities with higher confidence.
- You are writing a detailed report and want ATT&CK technique mappings.

In the classification verdict, capa results are factored in: five or more offensive capa capabilities boost the verdict. This means capa can push a "SUSPICIOUS" verdict up to "LIKELY MALICIOUS" when it detects capabilities that the behavioral rules missed.

---

## 6. Working with IOCs

The analyzer extracts nine categories of indicators. Here is how to use each one for threat hunting and response.

### URLs

**What it extracts:** HTTP and HTTPS URLs embedded in the binary's strings.

**Where to look them up:**
- [VirusTotal](https://www.virustotal.com) -- paste the URL directly
- [URLhaus](https://urlhaus.abuse.ch/) -- check if it is a known malware distribution URL
- [urlscan.io](https://urlscan.io) -- see a safe screenshot of what the URL serves

**How to use for threat hunting:**
```
# Splunk -- search proxy logs for connections to extracted URLs
index=proxy url="https://malicious-url.example.com/*"

# Elastic/KQL
url.original: "https://malicious-url.example.com/*"
```

**Action:** Block at the proxy/firewall. Add to your threat intelligence feed. Search historical logs to determine if any endpoint already contacted this URL.

### Domains

**What it extracts:** Domain names found in the binary (e.g., `evil.example.com`).

**Where to look them up:**
- [VirusTotal](https://www.virustotal.com) -- search the domain for reputation and history
- [RiskIQ/PassiveTotal](https://community.riskiq.com) -- passive DNS and WHOIS
- [Shodan](https://www.shodan.io) -- see what services the domain resolves to

**How to use for threat hunting:**
```
# Splunk -- search DNS logs
index=dns query="evil.example.com"

# Elastic/KQL
dns.question.name: "evil.example.com"
```

**Action:** Block at the DNS level (sinkhole the domain). Add to your domain blocklist. Check if the domain is newly registered (a common malware indicator).

### Embedded Credentials / Tokens

**What it extracts:** GitHub Personal Access Tokens (`github_pat_*`), GitHub tokens (`ghp_*`), and Bearer tokens found in the binary. Values are truncated to 60 characters to avoid accidental exposure.

**Where to look them up:**
- For GitHub tokens: [GitHub Token Settings](https://github.com/settings/tokens) -- check if the token belongs to an account in your organization.
- For generic Bearer tokens: determine what service they authenticate to (often visible from surrounding URL strings).

**How to use for threat hunting:**
```
# Splunk -- search for the token in authentication logs
index=github_audit token_prefix="github_pat_*"

# Search for lateral movement using stolen tokens
index=proxy request_header="Authorization: Bearer*"
```

**Action:** Revoke the token immediately. Audit what the token was used for. If it is a GitHub PAT, check the repository access logs for unauthorized activity. This is a critical finding -- embedded credentials in a binary mean the attacker has (or had) access to the associated account.

### User-Agent Strings

**What it extracts:** Custom User-Agent headers found in the binary.

**Where to look them up:** Search your proxy logs for the exact User-Agent string. Malware often uses distinctive or unusual User-Agent strings.

**How to use for threat hunting:**
```
# Splunk
index=proxy http_user_agent="Mozilla/5.0 (compatible; CustomBot/1.0)"

# Elastic/KQL
user_agent.original: "Mozilla/5.0 (compatible; CustomBot/1.0)"
```

**Action:** Add the User-Agent to your detection rules. A unique User-Agent is a reliable indicator because it is unlikely to match legitimate traffic.

### Windows File Paths

**What it extracts:** Paths like `C:\Users\...\AppData\Roaming\...` found in the binary.

**Where to look them up:** Search your EDR for files at these paths across your endpoint fleet.

**How to use for threat hunting:**
```
# Splunk (Sysmon file creation events)
index=sysmon EventCode=11 TargetFilename="C:\\Users\\*\\AppData\\Roaming\\malware_dir\\*"

# CrowdStrike Falcon
#event_simpleName=NewExecutableWritten FilePath="*\\AppData\\Roaming\\malware_dir\\*"
```

**Action:** If these paths exist on other endpoints, those systems may be compromised. The paths often reveal the malware's working directory, drop location, or data collection staging area.

### Registry Keys

**What it extracts:** References to `HKLM`, `HKCU`, and `HKEY_` registry paths.

**Where to look them up:** Search your EDR for these registry keys. Pay special attention to `CurrentVersion\Run` and `Services` keys, which indicate persistence.

**How to use for threat hunting:**
```
# Splunk (Sysmon registry events)
index=sysmon EventCode=13 TargetObject="*\\CurrentVersion\\Run\\*"

# Elastic/KQL
registry.path: "*\\CurrentVersion\\Run\\*"
```

**Action:** If persistence-related registry keys are found on other endpoints, those systems may be compromised. Remove the registry entry as part of remediation.

### OAuth / SSO Endpoints

**What it extracts:** Microsoft OAuth endpoints (`login.microsoftonline.com`), OAuth authorize URLs, SSO nonce references, client IDs, and redirect URIs.

**Where to look them up:** Check the client ID against your Azure AD / Entra ID application registrations. Determine whether the OAuth flow is targeting your organization's identity provider.

**How to use for threat hunting:**
```
# Splunk -- search Azure AD sign-in logs for the client ID
index=azure_ad client_id="extracted-client-id"

# Check for token phishing
index=proxy url="*login.microsoftonline.com*" NOT src_user=known_legitimate_app
```

**Action:** If the binary is performing OAuth flows, it may be a token phishing tool or a credential harvester disguised as a legitimate application. Check whether the redirect URI points to an attacker-controlled server. If it references your organization's tenant, investigate for unauthorized application registrations.

### UUIDs / GUIDs

**What it extracts:** UUIDs in standard format (8-4-4-4-12 hex digits).

**Where to look them up:** UUIDs can identify COM objects, COM classes, or malware configuration identifiers. Search for the UUID in Windows registry (`HKCR\CLSID\{uuid}`) to determine if it corresponds to a known COM object.

**How to use for threat hunting:** UUIDs are useful for correlating samples. If two different binaries contain the same unusual UUID, they are likely related.

**Action:** Lower priority than other IOC types. Use primarily for correlation and clustering.

### Environment Variables

**What it extracts:** References to environment variables like `%TEMP%`, `%APPDATA%`, `%USERPROFILE%`, etc.

**Where to look them up:** These tell you which directories the malware uses. `%TEMP%` and `%APPDATA%` are the most common malware staging directories.

**How to use for threat hunting:** Search your EDR for executable files created in the directories these variables resolve to.

**Action:** Lower priority on its own, but useful for understanding the malware's file system footprint.

---

## 7. Dealing with Packed Binaries

Packing is the single most common evasion technique. A packed binary wraps the real malware inside a compressed or encrypted container with a small unpacker stub. When you analyze a packed binary with this tool, the results will look very different from an unpacked one.

### How to recognize a packed binary

Look for this combination of indicators:

1. **High-entropy sections:** One or more sections with entropy above 7.0 (flagged in the sections table).
2. **Minimal imports:** The import table contains only a handful of functions -- typically just `LoadLibraryA`, `GetProcAddress`, `VirtualAlloc`, and `VirtualProtect`. These are the only functions the unpacker needs.
3. **Few meaningful strings:** Most extracted strings are generic or from the unpacker stub. You will not see URLs, file paths, or other indicators that would normally be present.
4. **Few behavioral rules firing:** Without visible imports and strings, most rules will not trigger.
5. **RWX sections:** A section with both Write and Execute permissions, where the unpacker will place the decompressed code.
6. **YARA packer matches:** If YARA is enabled, packer detection rules may identify the specific packer (UPX, Themida, VMProtect, ASPack, etc.).

### What the tool can still tell you

Even with a packed binary, the analyzer provides useful information:

- **Hashes:** You can still look up the packed binary on VirusTotal. Many AV engines detect packed malware even without unpacking.
- **Imphash:** The import hash of the unpacker stub can cluster related samples that use the same packer configuration.
- **Packer identification (YARA):** Knowing the packer tells you about the adversary's sophistication. Custom packers indicate a more advanced threat. Commodity packers (UPX) indicate less sophistication.
- **capa analysis:** capa can sometimes detect capabilities in the unpacker stub itself, or identify packing techniques.
- **Section analysis:** Entropy values and section permissions are visible regardless of packing.
- **Overlay data:** Packed binaries sometimes store the encrypted payload in the overlay (data appended after the PE structure). The overlay analysis will flag this.

### What the analyst should do

1. **Note the packing in your ticket.** "Binary is packed (entropy 7.85 in .text section, only 4 imports). Static analysis limited."
2. **Try to identify the packer.** Check YARA results and the compiler/packer detection section.
3. **For known packers, try static unpacking:**
   - UPX: `upx -d sample.exe -o sample_unpacked.exe`, then re-run the analyzer on the unpacked file.
   - For other packers, check if your team has unpacking tools.
4. **Submit to a sandbox for dynamic analysis.** ANY.RUN, Joe Sandbox, and similar platforms will observe the binary after it unpacks itself in memory. The sandbox report will show the real behavior.
5. **If you have Ghidra access,** running `--decompile ghidra` on a packed binary will not be very useful -- the decompiled code will mostly show the unpacker, not the payload.

### A note on "No strong indicators" + packing

When the verdict says "No strong indicators" and the binary is packed, this is NOT a clean bill of health. Write this in your report:

> "Static analysis produced no strong indicators of malicious behavior. However, the binary exhibits strong packing characteristics (high-entropy sections, minimal import table), which prevent static analysis from seeing the true functionality. Dynamic analysis is recommended."

---

## 8. .NET Binary Analysis

.NET executables are fundamentally different from native (C/C++) PE files. They contain rich metadata that makes static analysis much more productive.

### Why .NET is different

A native PE file compiles source code directly to machine instructions. The original variable names, class names, and method names are lost. A .NET PE file compiles to an intermediate language (IL) and retains all of its metadata: class names, method names, string constants, assembly references, and more. This metadata is required by the .NET runtime and cannot be stripped without breaking the program.

This means that analyzing a .NET binary gives you far more information than analyzing a native one.

### What the analyzer extracts from .NET binaries

When the analyzer detects a .NET binary (via the CLR runtime header), it automatically runs additional analysis:

**Metadata extraction (via dnfile):**
- **Module name** -- The internal name of the assembly.
- **Classes and types** -- Every class defined in the binary, with namespace and name.
- **Suspicious/obfuscated class names** -- Classes with very short names (1-2 characters) or non-ASCII characters, which indicate obfuscation.
- **Method analysis** -- Total method count and methods with suspicious names (containing words like Decrypt, Download, Execute, Inject, Steal, Keylog, Capture, etc.).
- **External references (MemberRef)** -- Functions called from external assemblies, including P/Invoke calls to native Windows APIs.
- **Assembly references** -- Which .NET assemblies the binary depends on. Non-standard assembly references are flagged.
- **User strings** -- String literals from the .NET string heap, filtered to interesting patterns (URLs, paths, commands, credentials).
- **Embedded resources** -- Data embedded in the assembly. Resources containing MZ headers (embedded PE files) or compressed archives are flagged.

**IL decompilation (via ilspycmd):**
- If `ilspycmd` is installed, the analyzer decompiles the .NET IL back to readable C# source code, saving it to a directory alongside the binary.

### Obfuscation indicators

Many .NET malware authors use obfuscation tools (ConfuserEx, .NET Reactor, Crypto Obfuscator, etc.) to make analysis harder. The analyzer flags these indicators:

- **Short class names:** Class names like `a`, `b`, `c` or single Unicode characters indicate that a rename obfuscator was used. Legitimate .NET code uses descriptive names.
- **Non-ASCII names:** Names containing Cyrillic, Chinese, or other non-Latin characters in class or method names often indicate obfuscation (or occasionally internationalization).
- **Suspicious method names:** Even after obfuscation, some methods retain meaningful names if they override framework methods or implement interfaces.

### Why .NET malware is often easier to analyze

Because .NET retains its metadata and can be decompiled back to nearly readable C# source code, .NET malware is generally much easier to analyze than native malware. The decompiled source code often includes:

- The actual C2 server URLs and API endpoints as string constants.
- The data collection logic in readable methods.
- The encryption/decryption routines with the keys sometimes visible.
- The exfiltration mechanism (HTTP POST, Discord webhook, Telegram bot, etc.).

### What the analyst should do

1. If the analyzer reports a .NET binary, focus on the **Method Analysis** section. Suspicious method names directly tell you what the malware does.
2. Read the **User Strings** section carefully. .NET strings are the richest source of IOCs in .NET malware.
3. If `ilspycmd` produced decompiled C# source, open it. Even without C# expertise, you can often understand the high-level logic from method and variable names.
4. Check the **Assembly References** for non-standard assemblies. References to assemblies like `System.Net.Http`, `System.Security.Cryptography`, or `System.IO.Compression` are not suspicious on their own, but references to unusual or custom assemblies may indicate additional functionality.
5. If class names are heavily obfuscated, note this as an indicator of malicious intent. Legitimate software has no reason to obfuscate its .NET metadata.

---

## 9. Common False Positives

The behavioral rules are designed to detect techniques that are more commonly associated with malware than with legitimate software. However, some legitimate software uses the same techniques for valid reasons. Here are the most common false positive scenarios and how to distinguish them from real threats.

### Installers and setup programs

**What triggers:** File enumeration, registry writes (`registry_autorun`), service creation (`service_creation`), file drops to Temp (`drops_to_temp`), process creation.

**Why it is legitimate:** Installers need to write files to disk, create registry entries, set up services, and sometimes create scheduled tasks. These are the core actions of any software installer.

**How to distinguish:** Check the version info -- legitimate installers typically identify their publisher. Check the digital signature (if present). Check the file's origin -- was it downloaded from the vendor's official website? Does the behavior match what you would expect from an installer for that specific software?

### Security software and admin tools

**What triggers:** Process inspection APIs (`token_manipulation`), memory read/write, `IsDebuggerPresent`, `OpenProcess`, screenshot APIs, keyboard hooks.

**Why it is legitimate:** Antivirus, EDR agents, remote management tools, and system administration utilities legitimately need to inspect running processes, read memory, and manage tokens.

**How to distinguish:** Check the publisher in the version info. Look at the digital signature. Verify the file hash against the vendor's published hashes. Security software from well-known vendors (CrowdStrike, SentinelOne, Microsoft Defender, etc.) will trigger many rules but is easily verified.

### Development and debugging tools

**What triggers:** `anti_debug_api`, memory manipulation, `VirtualAlloc`/`VirtualProtect`, `CreateRemoteThread`, `dynamic_api_resolution`.

**Why it is legitimate:** Debuggers (WinDbg, x64dbg), profilers, code injection frameworks (for testing), and development tools legitimately use these APIs.

**How to distinguish:** Context is everything. Was this found on a developer's workstation? Is it a known development tool? A copy of `windbg.exe` in `C:\Program Files` is normal. The same APIs imported by an unknown executable found in `C:\Users\Public\` is not.

### VPN and networking software

**What triggers:** Crypto APIs (`crypto_encrypt`, `crypto_decrypt`), network APIs (`winhttp_usage`, `raw_sockets`), certificate operations.

**Why it is legitimate:** VPN clients encrypt network traffic. This requires cryptographic APIs and network APIs working together.

**How to distinguish:** Verify the publisher and file origin. VPN software from known vendors will also have distinctive version info and digital signatures. The combination of crypto + network is only suspicious when there are additional indicators (credential theft, persistence, evasion).

### System utilities that ship with Windows

**What triggers:** Various rules depending on the utility. `schtasks.exe`, `wmic.exe`, `net.exe`, and `powershell.exe` will trigger multiple rules because they have the capability to perform actions malware also performs.

**Why it is legitimate:** These are built-in Windows tools with legitimate administrative uses.

**How to distinguish:** If the tool is in its normal location (`C:\Windows\System32\`) with the correct hash, it is the real tool. The question becomes: why was it called? Check the parent process and command-line arguments in your EDR logs. The tool itself is not malicious -- the way it was invoked may be.

### General guidance for handling false positives

Context always matters more than any single rule. Ask yourself:

1. **Who made it?** Check the version info, digital signature, and file origin.
2. **Where was it found?** A file in `Program Files` from a known vendor is very different from the same file in `C:\Users\Public` or `%TEMP%`.
3. **How did it get there?** Was it installed by an admin, downloaded by a user, or dropped by another process?
4. **Does the behavior match the purpose?** An installer that writes registry keys is normal. An "invoice.pdf.exe" that writes registry keys is not.
5. **What else is on the system?** A single false positive is one thing. Multiple suspicious files or behaviors on the same system suggest a real compromise.

---

## 10. Integration with Other Tools

The analyzer's JSON output is designed for machine consumption and is saved automatically on every run. Here is how to integrate it with the tools in your SOC stack.

### VirusTotal

**Hash lookups:**
```bash
# Look up the sample by SHA256
curl -s "https://www.virustotal.com/api/v3/files/$(jq -r '.hashes.sha256' sample_analysis.json)" \
  -H "x-apikey: YOUR_API_KEY" | jq '.data.attributes.last_analysis_stats'

# Search by imphash to find related samples
curl -s "https://www.virustotal.com/api/v3/search?query=imphash:$(jq -r '.imphash.imphash' sample_analysis.json)" \
  -H "x-apikey: YOUR_API_KEY"
```

**What to do with results:** VirusTotal detection ratios give you quick confidence. Community comments often identify the malware family. Behavioral reports from sandboxes complement your static analysis.

### SIEM (Splunk)

**Ingest IOCs from the JSON report:**
```bash
# Extract URLs for a Splunk lookup table
jq -r '.iocs.urls[]?' sample_analysis.json > /tmp/malware_urls.csv

# Extract all IOCs as a structured event
jq '{
  event_type: "pe_analysis",
  sha256: .hashes.sha256,
  verdict: (if (.behavior.behaviors | map(select(.severity == "critical")) | length) > 0 then "MALICIOUS"
            elif (.behavior.behaviors | map(select(.severity == "high")) | length) >= 2 then "LIKELY_MALICIOUS"
            else "SUSPICIOUS" end),
  urls: [.iocs.urls[]?],
  domains: [.iocs.domains[]?],
  registry_keys: [.iocs.registry_keys[]?],
  behaviors: [.behavior.behaviors[].rule]
}' sample_analysis.json
```

**Splunk search for IOC matches across your environment:**
```spl
| inputlookup malware_iocs.csv
| lookup dns_lookup domain AS ioc_domain OUTPUT src_ip, timestamp
| where isnotnull(src_ip)
| table timestamp, src_ip, ioc_domain
```

### SIEM (Elastic / OpenSearch)

**Ingest the full analysis:**
```bash
# Send the analysis to an Elastic index
curl -X POST "https://elastic:9200/pe_analysis/_doc" \
  -H "Content-Type: application/json" \
  -d @sample_analysis.json
```

**KQL hunt queries:**
```
# Find endpoints that contacted extracted domains
dns.question.name: ("domain1.example.com" OR "domain2.example.com")

# Find processes with matching hashes
process.hash.sha256: "abc123..."

# Find registry modifications matching extracted keys
registry.path: "*\\CurrentVersion\\Run\\*" AND registry.data.strings: "*malware_name*"
```

### SOAR (automated playbooks)

The JSON structure is consistent across every analysis run, making it suitable for automated playbooks:

```python
# Example: Python snippet for a SOAR playbook
import json

with open("sample_analysis.json") as f:
    report = json.load(f)

# Check verdict severity
critical_rules = [b for b in report["behavior"]["behaviors"] if b["severity"] == "critical"]
if critical_rules:
    # Trigger high-priority incident
    create_incident(severity="critical", title=f"Malicious PE detected: {report['hashes']['sha256'][:16]}...")

# Block extracted URLs
for url in report.get("iocs", {}).get("urls", []):
    firewall_block_url(url)

# Block extracted domains
for domain in report.get("iocs", {}).get("domains", []):
    dns_sinkhole(domain)
```

### Sandbox follow-up (ANY.RUN, Joe Sandbox)

When static analysis indicates packing or needs dynamic confirmation:

1. Submit the sample to your sandbox.
2. Compare the sandbox behavioral report with the static analysis findings. If the static analysis found injection APIs and the sandbox shows the binary injecting into `explorer.exe`, you have corroboration.
3. The sandbox may reveal additional IOCs (C2 servers contacted, files dropped, registry keys created) that the static analysis could not see due to packing.

### MISP (threat intelligence sharing)

Extract IOCs in a format suitable for MISP events:

```bash
# Generate MISP-compatible IOC list
jq '{
  info: ("PE Analysis: " + .hashes.sha256[:16] + "..."),
  attributes: (
    [.hashes | to_entries[] | {type: .key, value: .value, category: "Payload delivery"}] +
    [(.iocs.urls[]? // empty) | {type: "url", value: ., category: "Network activity"}] +
    [(.iocs.domains[]? // empty) | {type: "domain", value: ., category: "Network activity"}] +
    [{type: "imphash", value: .imphash.imphash, category: "Payload delivery"}]
  )
}' sample_analysis.json
```

### TheHive / Cortex

For case management with TheHive:

1. Create a new case for the suspicious PE.
2. Attach the JSON report as an observable.
3. Use Cortex analyzers to automatically enrich the hashes, URLs, and domains extracted by BAT.
4. The behavioral rule categories map directly to TheHive's TLP and PAP classification: critical-severity rules suggest TLP:RED and PAP:RED.

### Useful jq recipes for the JSON report

```bash
# List all triggered behavioral rules with severity
jq '.behavior.behaviors[] | "\(.severity | ascii_upcase): \(.description)"' sample_analysis.json

# Get only critical and high severity rules
jq '[.behavior.behaviors[] | select(.severity == "critical" or .severity == "high")]' sample_analysis.json

# Extract all IOC categories that have data
jq '.iocs | to_entries[] | select(.value | length > 0) | .key' sample_analysis.json

# Get section entropy values
jq '.sections[] | "\(.name): entropy \(.entropy)"' sample_analysis.json

# Check if binary is likely packed
jq 'if (.sections | map(select(.entropy > 7.0)) | length) > 0 then "LIKELY PACKED" else "NOT PACKED" end' sample_analysis.json

# Count behavioral rules by category
jq '[.behavior.behaviors[].category] | group_by(.) | map({category: .[0], count: length}) | sort_by(-.count)' sample_analysis.json

# Get capa ATT&CK mappings
jq '[.capa[]? | select(.["att&ck"]) | .["att&ck"][]] | unique' sample_analysis.json
```
