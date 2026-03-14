"""Generic behavioral rules — fire on techniques, not on any single malware family.
Grouped roughly by MITRE ATT&CK category."""

from bat_analyzer.context import AnalysisContext
from bat_analyzer.rules import Rule


def _check_version_mismatch(ctx: AnalysisContext) -> bool:
    """Generic masquerading: version info claims major vendor but binary has suspicious traits."""
    claimed = ctx.version_info.get("CompanyName", "").lower()
    known_vendors = ["microsoft", "adobe", "google", "mozilla", "apple"]
    if not any(v in claimed for v in known_vendors):
        return False
    return len(ctx.flat_imports) == 0 or any(
        s.get("entropy", 0) > 7.0 for s in ctx.sections
    )


GENERIC_RULES: list[Rule] = [

    # ══════════════════════════════════════════════════════════════════
    # INJECTION
    # ══════════════════════════════════════════════════════════════════
    Rule("process_injection", "injection", "high",
         "Classic process injection (VirtualAllocEx → WriteProcessMemory → CreateRemoteThread)",
         lambda ctx: ctx.has_all_imports("VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread")),

    Rule("apc_injection", "injection", "high",
         "APC injection via QueueUserAPC",
         lambda ctx: ctx.has_import("QueueUserAPC")),

    Rule("dll_injection", "injection", "high",
         "DLL injection via LoadLibrary + remote thread",
         lambda ctx: ctx.has_import("CreateRemoteThread")
                     and ctx.has_import("LoadLibraryA", "LoadLibraryW")),

    Rule("hook_injection", "injection", "medium",
         "Windows hook-based code injection",
         lambda ctx: ctx.has_import("SetWindowsHookExA", "SetWindowsHookExW")),

    Rule("ntcreatethread", "injection", "high",
         "Low-level thread creation in remote process",
         lambda ctx: ctx.has_import("NtCreateThreadEx", "RtlCreateUserThread")),

    Rule("process_hollowing", "injection", "critical",
         "Process hollowing (CreateProcess suspended → NtUnmapViewOfSection → write → resume)",
         lambda ctx: ctx.has_import("NtUnmapViewOfSection", "ZwUnmapViewOfSection")
                     and ctx.has_import("CreateProcessA", "CreateProcessW")),

    Rule("reflective_dll_injection", "injection", "critical",
         "Reflective DLL injection (loads DLL from memory without LoadLibrary)",
         lambda ctx: ctx.has_finding("reflective_injection")
                     or (ctx.has_string_containing("ReflectiveLoader"))),

    # ══════════════════════════════════════════════════════════════════
    # EVASION / ANTI-ANALYSIS
    # ══════════════════════════════════════════════════════════════════
    Rule("anti_debug_api", "evasion", "medium",
         "Debugger detection via API",
         lambda ctx: ctx.has_import("IsDebuggerPresent", "CheckRemoteDebuggerPresent")),

    Rule("anti_debug_nt", "evasion", "high",
         "Debugger detection via NtQueryInformationProcess",
         lambda ctx: ctx.has_import("NtQueryInformationProcess")),

    Rule("timing_evasion", "evasion", "low",
         "Timing-based sandbox/debugger detection",
         lambda ctx: ctx.has_all_imports("GetTickCount", "QueryPerformanceCounter")),

    Rule("anti_vm", "evasion", "medium",
         "Virtual machine / sandbox detection strings",
         lambda ctx: any(ctx.has_string_containing(vm) for vm in [
             "VMwareService", "VMwareTray", "VBoxService", "VBoxTray",
             "qemu-ga", "QEMU", "Sandboxie", "SbieDll", "cuckoomon",
             "wine_get_unix_file_name",
         ])),

    Rule("tls_callback", "evasion", "medium",
         "TLS callback may execute code before entry point",
         lambda ctx: hasattr(ctx.pe, "DIRECTORY_ENTRY_TLS") and bool(ctx.pe.DIRECTORY_ENTRY_TLS)),

    Rule("rwx_section", "evasion", "high",
         "Section with both WRITE and EXECUTE permissions",
         lambda ctx: ctx.any_section(
             lambda s: "EXEC" in s.get("characteristics", "") and "WRITE" in s.get("characteristics", ""))),

    Rule("high_entropy_section", "evasion", "medium",
         "Section with entropy > 7.0 (likely packed or encrypted)",
         lambda ctx: ctx.any_section(lambda s: s.get("entropy", 0) > 7.0)),

    Rule("no_import_table", "evasion", "high",
         "No import table — likely packed or manually resolves APIs",
         lambda ctx: len(ctx.flat_imports) == 0),

    Rule("direct_syscalls", "evasion", "high",
         "Uses direct NT syscalls (bypasses user-mode hooks / EDR)",
         lambda ctx: ctx.has_import(
             "NtAllocateVirtualMemory", "NtProtectVirtualMemory",
             "NtCreateSection", "NtWriteVirtualMemory",
         )),

    # ══════════════════════════════════════════════════════════════════
    # CREDENTIAL ACCESS
    # ══════════════════════════════════════════════════════════════════
    Rule("credential_api", "credential_theft", "high",
         "Credential enumeration / DPAPI decryption APIs",
         lambda ctx: ctx.has_import(
             "CredEnumerateA", "CredEnumerateW",
             "CryptUnprotectData",
             "LsaEnumerateLogonSessions",
         )),

    Rule("token_manipulation", "privilege_escalation", "high",
         "Token privilege escalation (OpenProcessToken + AdjustTokenPrivileges)",
         lambda ctx: ctx.has_all_imports("OpenProcessToken", "AdjustTokenPrivileges")),

    Rule("token_impersonation", "privilege_escalation", "high",
         "Token impersonation / duplication",
         lambda ctx: ctx.has_import("ImpersonateLoggedOnUser", "DuplicateTokenEx")),

    # ══════════════════════════════════════════════════════════════════
    # PERSISTENCE
    # ══════════════════════════════════════════════════════════════════
    Rule("registry_autorun", "persistence", "high",
         "Registry persistence via Run / RunOnce keys",
         lambda ctx: ctx.has_import("RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA", "RegCreateKeyExW")
                     and any(ctx.has_string_containing(k) for k in [
                         "\\Run", "\\RunOnce", "CurrentVersion\\Run",
                     ])),

    Rule("service_creation", "persistence", "high",
         "Persistence via Windows service creation",
         lambda ctx: ctx.has_import("CreateServiceA", "CreateServiceW")),

    Rule("scheduled_task", "persistence", "medium",
         "Scheduled task creation strings",
         lambda ctx: ctx.has_string_containing("schtasks") or ctx.has_string_containing("ITaskScheduler")),

    Rule("startup_folder", "persistence", "medium",
         "References to user Startup folder",
         lambda ctx: ctx.has_string_containing("\\Startup\\") or ctx.has_string_containing("\\Start Menu\\")),

    # ══════════════════════════════════════════════════════════════════
    # EXECUTION
    # ══════════════════════════════════════════════════════════════════
    Rule("process_creation", "execution", "medium",
         "Creates child processes",
         lambda ctx: ctx.has_import("CreateProcessA", "CreateProcessW", "WinExec")),

    Rule("shellexecute", "execution", "medium",
         "Launches programs via ShellExecute",
         lambda ctx: ctx.has_import("ShellExecuteA", "ShellExecuteW", "ShellExecuteExW")),

    Rule("dynamic_api_resolution", "execution", "medium",
         "Dynamically resolves APIs (GetProcAddress + LoadLibrary)",
         lambda ctx: ctx.has_all_imports("GetProcAddress", "LoadLibraryA")
                     or ctx.has_all_imports("GetProcAddress", "LoadLibraryW")),

    Rule("recon_commands", "discovery", "medium",
         "Contains reconnaissance commands (whoami, systeminfo, etc.)",
         lambda ctx: ctx.has_finding("recon_command")),

    Rule("powershell_execution", "execution", "high",
         "References PowerShell execution",
         lambda ctx: ctx.has_string_containing("powershell")
                     or ctx.has_string_containing("pwsh.exe")),

    # ══════════════════════════════════════════════════════════════════
    # NETWORK / C2
    # ══════════════════════════════════════════════════════════════════
    Rule("winhttp_usage", "network", "medium",
         "HTTP communication via WinHTTP",
         lambda ctx: ctx.has_import("WinHttpOpen", "WinHttpConnect")),

    Rule("wininet_usage", "network", "medium",
         "HTTP communication via WinINet",
         lambda ctx: ctx.has_import("InternetOpenA", "InternetOpenW")),

    Rule("url_download", "network", "high",
         "Downloads file from URL to disk",
         lambda ctx: ctx.has_import("URLDownloadToFileA", "URLDownloadToFileW")),

    Rule("raw_sockets", "network", "medium",
         "Raw socket usage (WSAStartup + connect)",
         lambda ctx: ctx.has_all_imports("WSAStartup", "connect")),

    Rule("embedded_urls", "network", "medium",
         "Contains embedded URLs",
         lambda ctx: ctx.has_finding("url")),

    Rule("named_pipe_c2", "network", "medium",
         "Named pipe communication (inter-process C2 or lateral movement)",
         lambda ctx: ctx.has_finding("named_pipe")),

    Rule("proxy_tunnel", "network", "high",
         "SOCKS proxy / tunnel capability",
         lambda ctx: ctx.has_finding("proxy_tunnel")),

    # ══════════════════════════════════════════════════════════════════
    # CRYPTO
    # ══════════════════════════════════════════════════════════════════
    Rule("crypto_encrypt", "crypto", "low",
         "Uses Windows Crypto API for encryption",
         lambda ctx: ctx.has_import("CryptEncrypt", "BCryptEncrypt")),

    Rule("crypto_decrypt", "crypto", "low",
         "Uses Windows Crypto API for decryption",
         lambda ctx: ctx.has_import("CryptDecrypt", "BCryptDecrypt")),

    Rule("base64_encoding", "encoding", "low",
         "Base64 encodes data via CryptBinaryToString",
         lambda ctx: ctx.has_import("CryptBinaryToStringA", "CryptBinaryToStringW")),

    # ══════════════════════════════════════════════════════════════════
    # MASQUERADING
    # ══════════════════════════════════════════════════════════════════
    Rule("version_mismatch", "masquerading", "high",
         "Version info claims known vendor but binary lacks expected characteristics",
         _check_version_mismatch),

    # ══════════════════════════════════════════════════════════════════
    # INFOSTEALER
    # ══════════════════════════════════════════════════════════════════
    Rule("browser_credential_theft", "credential_theft", "critical",
         "Targets browser credential databases (Login Data, cookies, Web Data)",
         lambda ctx: ctx.has_finding("browser_data") or ctx.has_finding("browser_db")),

    Rule("browser_path_access", "credential_theft", "high",
         "References browser profile paths (Chrome, Firefox, Edge, Brave, Opera)",
         lambda ctx: ctx.has_finding("browser_path")),

    Rule("browser_masterkey", "credential_theft", "critical",
         "Extracts browser master encryption key (encrypted_key from Local State)",
         lambda ctx: ctx.has_finding("browser_masterkey")),

    Rule("crypto_wallet_theft", "credential_theft", "critical",
         "Targets cryptocurrency wallet files or extensions",
         lambda ctx: ctx.has_finding("crypto_wallet") or ctx.has_finding("crypto_wallet_path")),

    Rule("discord_token_theft", "credential_theft", "high",
         "Targets Discord token storage (leveldb / Local Storage)",
         lambda ctx: ctx.has_finding("discord_data")),

    Rule("telegram_data_theft", "credential_theft", "high",
         "Targets Telegram Desktop session data (tdata)",
         lambda ctx: ctx.has_finding("telegram_data")),

    Rule("ftp_ssh_credential_theft", "credential_theft", "high",
         "Targets FTP/SSH saved credentials (FileZilla, WinSCP, PuTTY)",
         lambda ctx: ctx.has_finding("ftp_credentials") or ctx.has_finding("ssh_credentials")),

    Rule("email_client_theft", "credential_theft", "high",
         "Targets email client data (Outlook, Thunderbird)",
         lambda ctx: ctx.has_finding("email_client") or ctx.has_finding("outlook_data")),

    Rule("password_manager_targeting", "credential_theft", "critical",
         "Targets password manager data (KeePass, LastPass, Bitwarden, etc.)",
         lambda ctx: ctx.has_finding("password_manager")),

    Rule("vpn_credential_theft", "credential_theft", "high",
         "Targets VPN credentials (NordVPN, OpenVPN, ProtonVPN)",
         lambda ctx: ctx.has_finding("vpn_credentials")),

    Rule("keylogger", "credential_theft", "critical",
         "Keylogging APIs (GetAsyncKeyState / GetKeyboardState / keyboard hook)",
         lambda ctx: ctx.has_import("GetAsyncKeyState", "GetKeyState", "GetKeyboardState")),

    Rule("screenshot_capture", "collection", "high",
         "Screen capture via GDI (BitBlt + GetDesktopWindow)",
         lambda ctx: ctx.has_import("BitBlt") and ctx.has_import("GetDC", "GetDesktopWindow")),

    Rule("clipboard_theft", "collection", "medium",
         "Clipboard monitoring / theft",
         lambda ctx: ctx.has_all_imports("OpenClipboard", "GetClipboardData")),

    Rule("discord_webhook_exfil", "exfiltration", "critical",
         "Exfiltrates data via Discord webhook",
         lambda ctx: ctx.has_finding("discord_webhook")),

    Rule("telegram_bot_exfil", "exfiltration", "critical",
         "Exfiltrates data via Telegram bot API",
         lambda ctx: ctx.has_finding("telegram_bot_api")),

    Rule("file_upload_exfil", "exfiltration", "medium",
         "Uploads files via HTTP multipart (exfiltration indicator)",
         lambda ctx: ctx.has_finding("file_upload_header")),

    Rule("gaming_data_theft", "credential_theft", "medium",
         "Targets gaming platform data (Steam, Minecraft)",
         lambda ctx: ctx.has_finding("steam_data") or ctx.has_finding("gaming_data")),

    # ══════════════════════════════════════════════════════════════════
    # RANSOMWARE
    # ══════════════════════════════════════════════════════════════════
    Rule("shadow_copy_deletion", "impact", "critical",
         "Deletes Volume Shadow Copies (vssadmin / wmic shadowcopy delete)",
         lambda ctx: ctx.has_finding("shadow_copy_delete")),

    Rule("disable_recovery", "impact", "critical",
         "Disables Windows recovery via bcdedit",
         lambda ctx: ctx.has_finding("disable_recovery")),

    Rule("delete_backup_catalog", "impact", "high",
         "Deletes backup catalog (wbadmin delete catalog)",
         lambda ctx: ctx.has_finding("delete_backup_catalog")),

    Rule("ransom_note", "impact", "critical",
         "Contains ransom note text ('your files have been encrypted')",
         lambda ctx: ctx.has_finding("ransom_note") or ctx.has_finding("ransom_note_filename")),

    Rule("ransom_payment", "impact", "critical",
         "References cryptocurrency payment (bitcoin wallet / BTC address)",
         lambda ctx: ctx.has_finding("ransom_payment")
                     or ctx.has_finding("bitcoin_address")
                     or ctx.has_finding("bitcoin_bech32_address")
                     or ctx.has_finding("monero_address")),

    Rule("ransom_extension", "impact", "high",
         "References ransomware file extensions (.encrypted, .locked, .crypt)",
         lambda ctx: ctx.has_finding("ransom_extension")),

    Rule("bulk_file_encryption", "impact", "critical",
         "File enumeration + crypto APIs — likely ransomware encryption loop",
         lambda ctx: ctx.has_import("FindFirstFileW", "FindFirstFileA", "FindNextFileW", "FindNextFileA")
                     and ctx.has_import("CryptEncrypt", "BCryptEncrypt")),

    Rule("drive_enumeration", "discovery", "medium",
         "Enumerates logical drives (GetLogicalDriveStringsW)",
         lambda ctx: ctx.has_import("GetLogicalDriveStringsW")),

    Rule("safemode_boot", "impact", "high",
         "Configures safe mode boot (ransomware technique to bypass security software)",
         lambda ctx: ctx.has_finding("safemode_boot")),

    # ══════════════════════════════════════════════════════════════════
    # RAT / BACKDOOR
    # ══════════════════════════════════════════════════════════════════
    Rule("reverse_shell", "c2", "critical",
         "Reverse shell capability (cmd.exe + socket/pipe)",
         lambda ctx: ctx.has_finding("shell_command")
                     and (ctx.has_import("WSAStartup", "connect") or ctx.has_finding("named_pipe"))),

    Rule("webcam_capture", "collection", "high",
         "Webcam capture APIs (capCreateCaptureWindow)",
         lambda ctx: ctx.has_import("capCreateCaptureWindowA", "capCreateCaptureWindowW")
                     or ctx.has_finding("webcam_access")),

    Rule("audio_recording", "collection", "high",
         "Audio recording APIs (waveInOpen / mciSendString)",
         lambda ctx: ctx.has_import("waveInOpen", "mciSendStringA", "mciSendStringW")
                     or ctx.has_finding("audio_record")),

    Rule("remote_desktop_access", "c2", "high",
         "Remote desktop / VNC capability",
         lambda ctx: ctx.has_finding("remote_desktop")),

    Rule("file_manager_capability", "c2", "medium",
         "Remote file manager functionality (upload/download/list)",
         lambda ctx: ctx.has_finding("file_manager")),

    Rule("remote_input", "c2", "high",
         "Sends simulated keyboard/mouse input (remote control)",
         lambda ctx: ctx.has_import("keybd_event", "mouse_event", "SendInput")),

    # ══════════════════════════════════════════════════════════════════
    # LOADER / DROPPER
    # ══════════════════════════════════════════════════════════════════
    Rule("drops_to_temp", "execution", "high",
         "Drops executable to Temp / AppData directory",
         lambda ctx: ctx.has_finding("temp_drop_path")),

    Rule("embedded_pe", "resource_development", "high",
         "Contains embedded PE file (MZ header in strings/resources)",
         lambda ctx: ctx.has_finding("embedded_pe")),

    Rule("shellcode_execution", "execution", "critical",
         "VirtualAlloc + memcpy pattern — likely shellcode execution",
         lambda ctx: ctx.has_import("VirtualAlloc")
                     and ctx.has_import("VirtualProtect")
                     and not ctx.has_import("CreateRemoteThread")),

    # ══════════════════════════════════════════════════════════════════
    # ROOTKIT
    # ══════════════════════════════════════════════════════════════════
    Rule("driver_loading", "persistence", "critical",
         "Loads kernel driver (NtLoadDriver / ZwLoadDriver)",
         lambda ctx: ctx.has_import("NtLoadDriver", "ZwLoadDriver")
                     or ctx.has_finding("driver_load_string")),

    Rule("ssdt_hook", "evasion", "critical",
         "References SSDT / kernel service descriptor table hooking",
         lambda ctx: ctx.has_finding("ssdt_hook")),

    Rule("physical_drive_access", "impact", "critical",
         "Direct physical drive access (\\\\.\\PhysicalDrive) — wiper or bootkit",
         lambda ctx: ctx.has_finding("physical_drive_access")),

    Rule("physical_memory_access", "evasion", "critical",
         "Direct physical memory access (\\\\.\\PhysicalMemory)",
         lambda ctx: ctx.has_finding("physical_memory_access")),

    Rule("driver_path_reference", "persistence", "high",
         "References driver directory or driver registry keys",
         lambda ctx: ctx.has_finding("driver_path") or ctx.has_finding("driver_registry")),

    # ══════════════════════════════════════════════════════════════════
    # WORM / PROPAGATION
    # ══════════════════════════════════════════════════════════════════
    Rule("usb_propagation", "lateral_movement", "high",
         "USB / removable media propagation (autorun.inf or GetDriveType)",
         lambda ctx: ctx.has_finding("autorun_inf") or ctx.has_finding("usb_propagation")),

    Rule("network_share_propagation", "lateral_movement", "high",
         "Spreads via network shares (ADMIN$, IPC$, net share)",
         lambda ctx: ctx.has_finding("admin_share")
                     or ctx.has_finding("network_share_command")),

    Rule("network_enumeration", "discovery", "medium",
         "Enumerates network shares / servers",
         lambda ctx: ctx.has_finding("network_enumeration")
                     or ctx.has_import("NetShareEnum", "NetServerEnum", "WNetOpenEnum")),

    Rule("unc_path_access", "lateral_movement", "medium",
         "Accesses UNC paths (\\\\IP\\share)",
         lambda ctx: ctx.has_finding("unc_path")),

    Rule("email_worm", "lateral_movement", "high",
         "Email worm indicators (SMTP commands: MAIL FROM, RCPT TO)",
         lambda ctx: ctx.has_finding("email_worm")),

    # ══════════════════════════════════════════════════════════════════
    # MINER
    # ══════════════════════════════════════════════════════════════════
    Rule("crypto_miner", "impact", "critical",
         "Cryptocurrency mining software (xmrig, stratum protocol, mining pool)",
         lambda ctx: ctx.has_finding("mining_stratum")
                     or ctx.has_finding("mining_software")
                     or ctx.has_finding("mining_pool")),

    Rule("mining_algorithm", "impact", "high",
         "References mining algorithms (CryptoNight, RandomX, Ethash)",
         lambda ctx: ctx.has_finding("mining_algorithm")),

    Rule("miner_cli_args", "impact", "high",
         "Mining software CLI arguments (--donate-level, --threads, --algo)",
         lambda ctx: ctx.has_finding("miner_cli_args")),

    Rule("monero_wallet", "impact", "high",
         "Contains Monero wallet address",
         lambda ctx: ctx.has_finding("monero_address")),

    # ══════════════════════════════════════════════════════════════════
    # BANKING TROJAN
    # ══════════════════════════════════════════════════════════════════
    Rule("web_inject", "credential_theft", "critical",
         "Web injection / form grabbing (man-in-the-browser)",
         lambda ctx: ctx.has_finding("web_inject") or ctx.has_finding("form_grabber")),

    Rule("webinject_config", "credential_theft", "critical",
         "Web inject configuration (set_url, data_before, data_inject)",
         lambda ctx: ctx.has_finding("webinject_config")),

    Rule("banking_target", "credential_theft", "high",
         "References banking / financial institution names",
         lambda ctx: ctx.has_finding("banking_target")),

    Rule("certificate_install", "evasion", "high",
         "Installs certificates (MitM / traffic interception)",
         lambda ctx: ctx.has_finding("certificate_install")),

    Rule("http_hook", "credential_theft", "high",
         "Hooks HTTP request functions (traffic interception)",
         lambda ctx: ctx.has_finding("http_intercept")
                     or ctx.has_finding("browser_hook")),

    # ══════════════════════════════════════════════════════════════════
    # WIPER / DESTRUCTIVE
    # ══════════════════════════════════════════════════════════════════
    Rule("mbr_overwrite", "impact", "critical",
         "References MBR / Master Boot Record (bootkit or wiper)",
         lambda ctx: ctx.has_finding("mbr_reference")
                     and ctx.has_finding("physical_drive_access")),

    Rule("forced_shutdown", "impact", "high",
         "Forces system shutdown / reboot",
         lambda ctx: ctx.has_finding("forced_shutdown")),

    Rule("mass_file_deletion", "impact", "critical",
         "Mass file deletion commands (del /s /f, rmdir /s, Remove-Item -Recurse)",
         lambda ctx: ctx.has_finding("mass_delete_command")),

    Rule("secure_overwrite", "impact", "critical",
         "Secure file overwrite / wiping (cipher /w, SDelete)",
         lambda ctx: ctx.has_finding("secure_overwrite")),

    Rule("format_drive", "impact", "critical",
         "Formats disk drive (FORMAT command)",
         lambda ctx: ctx.has_finding("format_drive")),
]
