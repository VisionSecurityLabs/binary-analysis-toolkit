"""Static configuration — suspicious imports and string patterns."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class StringPattern:
    regex: str
    category: str
    weight: int = 1
    requires: list[str] = field(default_factory=list)


SUSPICIOUS_IMPORTS = {
    "injection": [
        "VirtualAllocEx", "WriteProcessMemory", "ReadProcessMemory",
        "CreateRemoteThread", "NtCreateThreadEx", "RtlCreateUserThread",
        "OpenProcess", "NtOpenProcess", "QueueUserAPC",
        "SetWindowsHookEx", "SetWindowsHookExA", "SetWindowsHookExW",
    ],
    "process": [
        "CreateProcessW", "CreateProcessA", "WinExec", "ShellExecuteW",
        "ShellExecuteA", "ShellExecuteExW",
    ],
    "process_hollowing": [
        "NtUnmapViewOfSection", "ZwUnmapViewOfSection",
        "NtMapViewOfSection", "ZwMapViewOfSection",
        "NtWriteVirtualMemory", "ZwWriteVirtualMemory",
        "NtResumeThread", "ZwResumeThread",
        "NtSetContextThread", "ZwSetContextThread",
        "NtGetContextThread", "ZwGetContextThread",
    ],
    "persistence": [
        "RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA",
        "RegCreateKeyExW", "CreateServiceW", "CreateServiceA",
    ],
    "credential_theft": [
        "CredEnumerateA", "CredEnumerateW", "CryptUnprotectData",
        "LsaEnumerateLogonSessions", "SamEnumerateUsersInDomain",
        "CryptProtectData", "CryptUnprotectMemory",
        # Clipboard
        "OpenClipboard", "GetClipboardData",
        # Screenshot
        "BitBlt", "GetDC", "GetDesktopWindow", "CreateCompatibleBitmap",
        # Keylogging
        "GetAsyncKeyState", "GetKeyState", "GetKeyboardState",
    ],
    "network": [
        "WinHttpOpen", "WinHttpConnect", "WinHttpOpenRequest",
        "WinHttpSendRequest", "WinHttpReceiveResponse", "WinHttpReadData",
        "InternetOpenA", "InternetOpenW", "InternetConnectA",
        "InternetConnectW", "HttpOpenRequestA", "HttpSendRequestA",
        "URLDownloadToFileA", "URLDownloadToFileW",
        "WSAStartup", "connect", "send", "recv",
    ],
    "crypto": [
        "CryptEncrypt", "CryptDecrypt", "CryptAcquireContextA",
        "CryptBinaryToStringA", "CryptStringToBinaryA",
        "BCryptEncrypt", "BCryptDecrypt", "BCryptGenRandom",
    ],
    "evasion": [
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess", "GetTickCount", "QueryPerformanceCounter",
        "VirtualProtect", "VirtualQuery",
    ],
    "token_manipulation": [
        "OpenProcessToken", "AdjustTokenPrivileges",
        "LookupPrivilegeValueA", "ImpersonateLoggedOnUser",
        "DuplicateTokenEx",
    ],
    "com": [
        "CoCreateInstance", "CoInitializeEx", "CoCreateGuid",
    ],
    # ── RAT / Backdoor ──
    "rat_webcam": [
        "capCreateCaptureWindowA", "capCreateCaptureWindowW",
        "capGetDriverDescriptionA",
    ],
    "rat_audio": [
        "waveInOpen", "waveInStart", "waveInClose",
        "mciSendStringA", "mciSendStringW",
    ],
    "rat_desktop": [
        "CreateDesktopA", "CreateDesktopW", "SwitchDesktop",
        "GetForegroundWindow", "SetForegroundWindow",
        "keybd_event", "mouse_event", "SendInput",
    ],
    # ── Rootkit / Driver ──
    "driver_loading": [
        "NtLoadDriver", "ZwLoadDriver",
        "NtSystemDebugControl", "ZwSystemDebugControl",
    ],
    "direct_syscall": [
        "NtAllocateVirtualMemory", "NtProtectVirtualMemory",
        "NtCreateSection", "NtOpenSection",
        "NtCreateFile", "NtReadFile", "NtWriteFile",
        "NtClose", "NtQuerySystemInformation",
        "NtQueryVirtualMemory", "NtFreeVirtualMemory",
    ],
    # ── Wiper / Destructive ──
    "wiper": [
        "CreateFileA", "CreateFileW",  # generic but scored in context
        "SetFilePointer", "SetFilePointerEx",
        "DeviceIoControl",
        "InitiateSystemShutdownExW", "ExitWindowsEx",
    ],
    # ── Ransomware ──
    "file_enumeration": [
        "FindFirstFileA", "FindFirstFileW",
        "FindNextFileA", "FindNextFileW",
        "FindFirstFileExW",
        "GetLogicalDriveStringsW", "GetDriveTypeW",
    ],
}

SUSPICIOUS_STRING_PATTERNS = [
    # ── URLs and domains ──
    StringPattern(r'https?://[^\x00\s]{5,200}', "url", 4),
    StringPattern(
        r'[a-zA-Z0-9][-a-zA-Z0-9]{1,}\.(com|net|org|io|xyz|top|ru|cn|tk|onion)\b',
        "domain", 2,
        requires=["url", "user_agent", "github_api", "ms_oauth"],
    ),
    # ── Credentials and tokens ──
    StringPattern(r'github_pat_[A-Za-z0-9_]{30,}', "github_pat", 10),
    StringPattern(r'ghp_[A-Za-z0-9]{36}', "github_token", 2),
    StringPattern(r'Bearer\s+[A-Za-z0-9._\-]+', "bearer_token", 4),
    StringPattern(r'Authorization:\s*.+', "auth_header", 4),
    StringPattern(
        r'[A-Za-z0-9+/]{40,}={1,2}|[A-Za-z0-9+/]*[+/][A-Za-z0-9+/]{39,}={0,2}',
        "possible_base64", 2,
    ),
    # ── API and C2 ──
    StringPattern(r'api\.github\.com', "github_api", 6),
    StringPattern(r'/repos/[^\x00\s]+', "github_repo_path", 6),
    StringPattern(r'/contents/[^\x00\s]+', "github_contents_path", 6),
    StringPattern(r'User-Agent:\s*.+', "user_agent", 4),
    StringPattern(r'Content-Type:\s*.+', "content_type_header", 2),
    StringPattern(r'Accept:\s*.+', "accept_header", 2),
    # ── OAuth / SSO ──
    StringPattern(r'login\.microsoftonline\.com', "ms_oauth", 4),
    StringPattern(r'oauth2?/authorize', "oauth_endpoint", 4),
    StringPattern(r'sso_nonce', "sso_nonce", 4),
    StringPattern(r'client_id=[^\x00\s&]+', "client_id", 2),
    StringPattern(r'redirect_uri=[^\x00\s&]+', "redirect_uri", 2),
    StringPattern(
        r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', "uuid", 2,
        requires=["ms_oauth", "com", "browser_data", "discord_data"],
    ),
    # ── File system ──
    StringPattern(
        r'C:\\[^\x00]{5,}', "windows_path", 2,
        requires=["browser_path", "temp_drop_path", "driver_path", "crypto_wallet_path", "shell_command"],
    ),
    StringPattern(
        r'%[A-Z]+%', "env_variable", 2,
        requires=["temp_drop_path", "shell_command", "recon_command"],
    ),
    StringPattern(
        r'HKLM|HKCU|HKEY_', "registry_key", 2,
        requires=["browser_path", "browser_data", "persistence", "driver_registry", "vpn_credentials"],
    ),
    # ── JSON structures ──
    StringPattern(
        r'\{"[a-z_]+":', "json_object", 2,
        requires=["url", "github_api", "user_agent", "discord_webhook", "telegram_bot_api"],
    ),
    StringPattern(
        r'"message":', "json_message_key", 2,
        requires=["url", "github_api", "user_agent"],
    ),
    StringPattern(
        r'"content":', "json_content_key", 2,
        requires=["url", "github_api", "github_contents_path"],
    ),
    StringPattern(
        r'"branch":', "json_branch_key", 2,
        requires=["github_api", "github_repo_path"],
    ),
    # ── Recon ──
    StringPattern(
        r'whoami|systeminfo|ipconfig|hostname|tasklist|wmic', "recon_command", 4,
        requires=["shell_command", "network"],
    ),

    # ══════════════════════════════════════════════════════════════════
    # INFOSTEALER TARGETS
    # ══════════════════════════════════════════════════════════════════
    # Browser data paths
    StringPattern(r'Login Data|Web Data|Cookies|History|Local State|Bookmarks', "browser_data", 6),
    StringPattern(r'Google\\\\Chrome|Mozilla\\\\Firefox|Microsoft\\\\Edge|BraveSoftware|Opera', "browser_path", 6),
    StringPattern(r'logins\.json|cookies\.sqlite|key[34]\.db|cert[89]\.db|signons\.sqlite', "browser_db", 6),
    StringPattern(r'profiles\.ini|places\.sqlite', "firefox_profile", 2),
    StringPattern(r'encrypted_key', "browser_masterkey", 8),
    # Crypto wallets
    StringPattern(r'wallet\.dat|Electrum|Exodus|Metamask|Atomic Wallet|Coinomi', "crypto_wallet", 8),
    StringPattern(r'solana|phantom|trust.wallet|Jaxx|Wasabi', "crypto_wallet", 8),
    StringPattern(r'\\\\Ethereum\\\\keystore|\\\\Monero\\\\wallets', "crypto_wallet_path", 2),
    # Messaging / Discord / Telegram
    StringPattern(r'Telegram Desktop|\\\\tdata\\\\', "telegram_data", 6),
    StringPattern(r'discord(?:canary|ptb)?\\\\Local Storage|leveldb', "discord_data", 6),
    StringPattern(r'discordapp\.com/api/webhooks', "discord_webhook", 10),
    StringPattern(r'api\.telegram\.org/bot', "telegram_bot_api", 10),
    StringPattern(r'Signal\\\\sql\\\\db\.sqlite', "signal_data", 2),
    # FTP / SSH clients
    StringPattern(r'FileZilla\\\\recentservers\.xml|FileZilla\\\\sitemanager\.xml', "ftp_credentials", 8),
    StringPattern(r'WinSCP\.ini|WinSCP\\\\Sessions', "ftp_credentials", 8),
    StringPattern(r'PuTTY\\\\Sessions|SimonTatham\\\\PuTTY', "ssh_credentials", 8),
    # Email clients
    StringPattern(r'Thunderbird\\\\Profiles|\\\\Mail\\\\', "email_client", 6),
    StringPattern(r'Microsoft\\\\Outlook|Software\\\\Microsoft\\\\Office.*Outlook', "outlook_data", 6),
    # Gaming platforms
    StringPattern(r'Steam\\\\config|steamapps|ssfn', "steam_data", 2),
    StringPattern(r'\.minecraft\\\\launcher_profiles', "gaming_data", 2),
    # VPN
    StringPattern(r'NordVPN|OpenVPN|ProtonVPN|Windscribe', "vpn_credentials", 6),
    # Password managers
    StringPattern(r'KeePass|LastPass|1Password|Bitwarden|Dashlane', "password_manager", 6),
    # Exfiltration indicators
    StringPattern(r'Content-Disposition.*attachment', "file_upload_header", 4),
    StringPattern(r'multipart/form-data', "file_upload_header", 4),

    # ══════════════════════════════════════════════════════════════════
    # RANSOMWARE
    # ══════════════════════════════════════════════════════════════════
    StringPattern(r'vssadmin\s+delete\s+shadows', "shadow_copy_delete", 10),
    StringPattern(r'wmic\s+shadowcopy\s+delete', "shadow_copy_delete", 10),
    StringPattern(r'bcdedit\s+/set\s+\{default\}\s+recoveryenabled\s+no', "disable_recovery", 6),
    StringPattern(r'bcdedit\s+/set\s+\{default\}\s+bootstatuspolicy\s+ignoreallfailures', "disable_recovery", 6),
    StringPattern(r'wbadmin\s+delete\s+catalog', "delete_backup_catalog", 6),
    StringPattern(r'Your files have been encrypted', "ransom_note", 10),
    StringPattern(r'All your files are encrypted', "ransom_note", 10),
    StringPattern(r'pay.*bitcoin|bitcoin.*wallet|BTC.*address', "ransom_payment", 6),
    StringPattern(r'\.encrypted|\.locked|\.crypt|\.enc$', "ransom_extension", 6),
    StringPattern(r'DECRYPT|RECOVER|README.*txt|HOW.TO.*DECRYPT', "ransom_note_filename", 6),
    StringPattern(r'[13][a-km-zA-HJ-NP-Z1-9]{25,34}', "bitcoin_address", 6),
    StringPattern(r'0x[0-9a-fA-F]{40}', "ethereum_address", 6),
    StringPattern(r'bc1[a-zA-HJ-NP-Z0-9]{39,59}', "bitcoin_bech32_address", 6),
    StringPattern(r'safemode|SafeBoot|bcdedit.*/set.*safeboot', "safemode_boot", 6),

    # ══════════════════════════════════════════════════════════════════
    # RAT / BACKDOOR
    # ══════════════════════════════════════════════════════════════════
    StringPattern(r'cmd\.exe|powershell\.exe|pwsh\.exe', "shell_command", 4),
    StringPattern(r'\\\\pipe\\\\', "named_pipe", 4),
    StringPattern(r'reverse.*shell|bind.*shell|shell.*reverse', "reverse_shell", 6),
    StringPattern(r'webcam|camera|capture.*video', "webcam_access", 4),
    StringPattern(r'microphone|audio.*record|wave.*in', "audio_record", 4),
    StringPattern(r'keylog|key.*log|keyboard.*hook', "keylogger_string", 6),
    StringPattern(r'screen.*capture|screenshot|desktop.*capture', "screenshot_string", 6),
    StringPattern(r'file.*manager|dir.*listing|upload.*file|download.*file', "file_manager", 4),
    StringPattern(r'remote.*desktop|rdp|vnc', "remote_desktop", 4),
    StringPattern(r'SOCKS[45]|proxy.*tunnel', "proxy_tunnel", 4),

    # ══════════════════════════════════════════════════════════════════
    # LOADER / DROPPER
    # ══════════════════════════════════════════════════════════════════
    StringPattern(r'MZ.*This program', "embedded_pe", 6),
    StringPattern(r'ReflectiveLoader|reflective.*dll', "reflective_injection", 10),
    StringPattern(r'\\\\Temp\\\\.*\.exe|\\\\Temp\\\\.*\.dll', "temp_drop_path", 6),
    StringPattern(r'%TEMP%.*\.exe|%APPDATA%.*\.exe', "temp_drop_path", 6),
    StringPattern(r'NtUnmapViewOfSection|ZwUnmapViewOfSection', "process_hollowing_string", 10),
    StringPattern(r'RunPE|process.*hollow', "process_hollowing_string", 10),

    # ══════════════════════════════════════════════════════════════════
    # ROOTKIT
    # ══════════════════════════════════════════════════════════════════
    StringPattern(r'\\\\.\\\\PhysicalDrive[0-9]', "physical_drive_access", 8),
    StringPattern(r'\\\\.\\\\PhysicalMemory', "physical_memory_access", 8),
    StringPattern(r'\\\\Device\\\\', "device_path", 2),
    StringPattern(r'KeServiceDescriptorTable|SSDT', "ssdt_hook", 8),
    StringPattern(r'\\\\SystemRoot\\\\System32\\\\drivers', "driver_path", 6),
    StringPattern(r'NtLoadDriver|ZwLoadDriver', "driver_load_string", 8),
    StringPattern(r'\\\\Registry\\\\Machine\\\\System.*Services', "driver_registry", 6),

    # ══════════════════════════════════════════════════════════════════
    # WORM / PROPAGATION
    # ══════════════════════════════════════════════════════════════════
    StringPattern(r'autorun\.inf', "autorun_inf", 6),
    StringPattern(r'\\\\\\\\[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\\\\', "unc_path", 4),
    StringPattern(r'net\s+share|net\s+use', "network_share_command", 4),
    StringPattern(
        r'IPC\$|ADMIN\$|C\$', "admin_share", 4,
        requires=["network_share_command", "network_enumeration", "unc_path"],
    ),
    StringPattern(r'NetShareEnum|NetServerEnum|WNetOpenEnum', "network_enumeration", 6),
    StringPattern(r'smtp|MAIL\s+FROM|RCPT\s+TO|EHLO|HELO', "email_worm", 6),
    StringPattern(r'USB|removable|GetDriveType', "usb_propagation", 2),

    # ══════════════════════════════════════════════════════════════════
    # MINER
    # ══════════════════════════════════════════════════════════════════
    StringPattern(r'stratum\+tcp://|stratum\+ssl://', "mining_stratum", 10),
    StringPattern(r'xmrig|cpuminer|cgminer|bfgminer|ethminer|PhoenixMiner', "mining_software", 6),
    StringPattern(r'pool\.minexmr|nanopool\.org|2miners\.com|f2pool|hashvault', "mining_pool", 6),
    StringPattern(r'4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}', "monero_address", 6),
    StringPattern(r'--donate-level|--threads|--cpu-priority|--algo', "miner_cli_args", 6),
    StringPattern(r'CryptoNight|RandomX|Ethash|KawPow', "mining_algorithm", 6),

    # ══════════════════════════════════════════════════════════════════
    # BANKING TROJAN
    # ══════════════════════════════════════════════════════════════════
    StringPattern(r'inject.*html|webinject|web.*inject', "web_inject", 8),
    StringPattern(r'form.*grab|formgrab|POST.*data.*intercept', "form_grabber", 4),
    StringPattern(r'InternetSetStatusCallback|HttpAddRequestHeaders', "browser_hook", 4),
    StringPattern(
        r'bank|paypal|chase|wellsfargo|citibank', "banking_target", 6,
        requires=["browser_hook", "web_inject", "form_grabber", "webinject_config", "http_intercept"],
    ),
    StringPattern(r'set_url|data_before|data_after|data_inject', "webinject_config", 8),
    StringPattern(r'HttpSendRequestA|HttpSendRequestW', "http_intercept", 4),
    StringPattern(r'certutil|InstallCert|AddCert', "certificate_install", 6),

    # ══════════════════════════════════════════════════════════════════
    # WIPER / DESTRUCTIVE
    # ══════════════════════════════════════════════════════════════════
    StringPattern(r'\\\\.\\\\PhysicalDrive', "physical_drive_access", 8),
    StringPattern(r'MBR|Master Boot Record|\\\\MBR', "mbr_reference", 6),
    StringPattern(r'InitiateSystemShutdown|ExitWindowsEx|NtShutdownSystem', "forced_shutdown", 4),
    StringPattern(r'FORMAT\s+[A-Z]:', "format_drive", 6),
    StringPattern(r'del\s+/[sf]|rmdir\s+/[sq]|Remove-Item.*-Recurse', "mass_delete_command", 8),
    StringPattern(r'cipher\s+/w:', "secure_overwrite", 8),
    StringPattern(r'SDelete|sdelete|overwrite', "secure_overwrite", 8),
]
