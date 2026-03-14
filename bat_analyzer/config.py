"""Static configuration — suspicious imports and string patterns."""

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
    (r'https?://[^\x00\s]{5,200}', "url", 4),
    (r'[a-zA-Z0-9-]+\.(com|net|org|io|xyz|top|ru|cn|tk|onion)', "domain", 2),
    # ── Credentials and tokens ──
    (r'github_pat_[A-Za-z0-9_]{30,}', "github_pat", 10),
    (r'ghp_[A-Za-z0-9]{36}', "github_token", 2),
    (r'Bearer\s+[A-Za-z0-9._\-]+', "bearer_token", 4),
    (r'Authorization:\s*.+', "auth_header", 4),
    (r'[A-Za-z0-9+/]{40,}={0,2}', "possible_base64", 2),
    # ── API and C2 ──
    (r'api\.github\.com', "github_api", 6),
    (r'/repos/[^\x00\s]+', "github_repo_path", 6),
    (r'/contents/[^\x00\s]+', "github_contents_path", 6),
    (r'User-Agent:\s*.+', "user_agent", 4),
    (r'Content-Type:\s*.+', "content_type_header", 2),
    (r'Accept:\s*.+', "accept_header", 2),
    # ── OAuth / SSO ──
    (r'login\.microsoftonline\.com', "ms_oauth", 4),
    (r'oauth2?/authorize', "oauth_endpoint", 4),
    (r'sso_nonce', "sso_nonce", 4),
    (r'client_id=[^\x00\s&]+', "client_id", 2),
    (r'redirect_uri=[^\x00\s&]+', "redirect_uri", 2),
    (r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', "uuid", 2),
    # ── File system ──
    (r'C:\\[^\x00]{5,}', "windows_path", 2),
    (r'%[A-Z]+%', "env_variable", 2),
    (r'HKLM|HKCU|HKEY_', "registry_key", 2),
    # ── JSON structures ──
    (r'\{"[a-z_]+":', "json_object", 2),
    (r'"message":', "json_message_key", 2),
    (r'"content":', "json_content_key", 2),
    (r'"branch":', "json_branch_key", 2),
    # ── Recon ──
    (r'whoami|systeminfo|ipconfig|hostname|tasklist|wmic', "recon_command", 4),

    # ══════════════════════════════════════════════════════════════════
    # INFOSTEALER TARGETS
    # ══════════════════════════════════════════════════════════════════
    # Browser data paths
    (r'Login Data|Web Data|Cookies|History|Local State|Bookmarks', "browser_data", 6),
    (r'Google\\\\Chrome|Mozilla\\\\Firefox|Microsoft\\\\Edge|BraveSoftware|Opera', "browser_path", 6),
    (r'logins\.json|cookies\.sqlite|key[34]\.db|cert[89]\.db|signons\.sqlite', "browser_db", 6),
    (r'profiles\.ini|places\.sqlite', "firefox_profile", 2),
    (r'encrypted_key', "browser_masterkey", 8),
    # Crypto wallets
    (r'wallet\.dat|Electrum|Exodus|Metamask|Atomic Wallet|Coinomi', "crypto_wallet", 8),
    (r'solana|phantom|trust.wallet|Jaxx|Wasabi', "crypto_wallet", 8),
    (r'\\\\Ethereum\\\\keystore|\\\\Monero\\\\wallets', "crypto_wallet_path", 2),
    # Messaging / Discord / Telegram
    (r'Telegram Desktop|\\\\tdata\\\\', "telegram_data", 6),
    (r'discord(?:canary|ptb)?\\\\Local Storage|leveldb', "discord_data", 6),
    (r'discordapp\.com/api/webhooks', "discord_webhook", 10),
    (r'api\.telegram\.org/bot', "telegram_bot_api", 10),
    (r'Signal\\\\sql\\\\db\.sqlite', "signal_data", 2),
    # FTP / SSH clients
    (r'FileZilla\\\\recentservers\.xml|FileZilla\\\\sitemanager\.xml', "ftp_credentials", 8),
    (r'WinSCP\.ini|WinSCP\\\\Sessions', "ftp_credentials", 8),
    (r'PuTTY\\\\Sessions|SimonTatham\\\\PuTTY', "ssh_credentials", 8),
    # Email clients
    (r'Thunderbird\\\\Profiles|\\\\Mail\\\\', "email_client", 6),
    (r'Microsoft\\\\Outlook|Software\\\\Microsoft\\\\Office.*Outlook', "outlook_data", 6),
    # Gaming platforms
    (r'Steam\\\\config|steamapps|ssfn', "steam_data", 2),
    (r'\.minecraft\\\\launcher_profiles', "gaming_data", 2),
    # VPN
    (r'NordVPN|OpenVPN|ProtonVPN|Windscribe', "vpn_credentials", 6),
    # Password managers
    (r'KeePass|LastPass|1Password|Bitwarden|Dashlane', "password_manager", 6),
    # Exfiltration indicators
    (r'Content-Disposition.*attachment', "file_upload_header", 4),
    (r'multipart/form-data', "file_upload_header", 4),

    # ══════════════════════════════════════════════════════════════════
    # RANSOMWARE
    # ══════════════════════════════════════════════════════════════════
    (r'vssadmin\s+delete\s+shadows', "shadow_copy_delete", 10),
    (r'wmic\s+shadowcopy\s+delete', "shadow_copy_delete", 10),
    (r'bcdedit\s+/set\s+\{default\}\s+recoveryenabled\s+no', "disable_recovery", 6),
    (r'bcdedit\s+/set\s+\{default\}\s+bootstatuspolicy\s+ignoreallfailures', "disable_recovery", 6),
    (r'wbadmin\s+delete\s+catalog', "delete_backup_catalog", 6),
    (r'Your files have been encrypted', "ransom_note", 10),
    (r'All your files are encrypted', "ransom_note", 10),
    (r'pay.*bitcoin|bitcoin.*wallet|BTC.*address', "ransom_payment", 6),
    (r'\.encrypted|\.locked|\.crypt|\.enc$', "ransom_extension", 6),
    (r'DECRYPT|RECOVER|README.*txt|HOW.TO.*DECRYPT', "ransom_note_filename", 6),
    (r'[13][a-km-zA-HJ-NP-Z1-9]{25,34}', "bitcoin_address", 6),
    (r'0x[0-9a-fA-F]{40}', "ethereum_address", 6),
    (r'bc1[a-zA-HJ-NP-Z0-9]{39,59}', "bitcoin_bech32_address", 6),
    (r'safemode|SafeBoot|bcdedit.*/set.*safeboot', "safemode_boot", 6),

    # ══════════════════════════════════════════════════════════════════
    # RAT / BACKDOOR
    # ══════════════════════════════════════════════════════════════════
    (r'cmd\.exe|powershell\.exe|pwsh\.exe', "shell_command", 4),
    (r'\\\\pipe\\\\', "named_pipe", 4),
    (r'reverse.*shell|bind.*shell|shell.*reverse', "reverse_shell", 6),
    (r'webcam|camera|capture.*video', "webcam_access", 4),
    (r'microphone|audio.*record|wave.*in', "audio_record", 4),
    (r'keylog|key.*log|keyboard.*hook', "keylogger_string", 6),
    (r'screen.*capture|screenshot|desktop.*capture', "screenshot_string", 6),
    (r'file.*manager|dir.*listing|upload.*file|download.*file', "file_manager", 4),
    (r'remote.*desktop|rdp|vnc', "remote_desktop", 4),
    (r'SOCKS[45]|proxy.*tunnel', "proxy_tunnel", 4),

    # ══════════════════════════════════════════════════════════════════
    # LOADER / DROPPER
    # ══════════════════════════════════════════════════════════════════
    (r'MZ.*This program', "embedded_pe", 6),
    (r'ReflectiveLoader|reflective.*dll', "reflective_injection", 10),
    (r'\\\\Temp\\\\.*\.exe|\\\\Temp\\\\.*\.dll', "temp_drop_path", 6),
    (r'%TEMP%.*\.exe|%APPDATA%.*\.exe', "temp_drop_path", 6),
    (r'NtUnmapViewOfSection|ZwUnmapViewOfSection', "process_hollowing_string", 10),
    (r'RunPE|process.*hollow', "process_hollowing_string", 10),

    # ══════════════════════════════════════════════════════════════════
    # ROOTKIT
    # ══════════════════════════════════════════════════════════════════
    (r'\\\\.\\\\PhysicalDrive[0-9]', "physical_drive_access", 8),
    (r'\\\\.\\\\PhysicalMemory', "physical_memory_access", 8),
    (r'\\\\Device\\\\', "device_path", 2),
    (r'KeServiceDescriptorTable|SSDT', "ssdt_hook", 8),
    (r'\\\\SystemRoot\\\\System32\\\\drivers', "driver_path", 6),
    (r'NtLoadDriver|ZwLoadDriver', "driver_load_string", 8),
    (r'\\\\Registry\\\\Machine\\\\System.*Services', "driver_registry", 6),

    # ══════════════════════════════════════════════════════════════════
    # WORM / PROPAGATION
    # ══════════════════════════════════════════════════════════════════
    (r'autorun\.inf', "autorun_inf", 6),
    (r'\\\\\\\\[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\\\\', "unc_path", 4),
    (r'net\s+share|net\s+use', "network_share_command", 4),
    (r'IPC\$|ADMIN\$|C\$', "admin_share", 4, ["network_share_command", "network_enumeration", "unc_path"]),
    (r'NetShareEnum|NetServerEnum|WNetOpenEnum', "network_enumeration", 6),
    (r'smtp|MAIL FROM|RCPT TO|EHLO|HELO', "email_worm", 6),
    (r'USB|removable|GetDriveType', "usb_propagation", 2),

    # ══════════════════════════════════════════════════════════════════
    # MINER
    # ══════════════════════════════════════════════════════════════════
    (r'stratum\+tcp://|stratum\+ssl://', "mining_stratum", 10),
    (r'xmrig|cpuminer|cgminer|bfgminer|ethminer|PhoenixMiner', "mining_software", 6),
    (r'pool\.minexmr|nanopool\.org|2miners\.com|f2pool|hashvault', "mining_pool", 6),
    (r'4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}', "monero_address", 6),
    (r'--donate-level|--threads|--cpu-priority|--algo', "miner_cli_args", 6),
    (r'CryptoNight|RandomX|Ethash|KawPow', "mining_algorithm", 6),

    # ══════════════════════════════════════════════════════════════════
    # BANKING TROJAN
    # ══════════════════════════════════════════════════════════════════
    (r'inject.*html|webinject|web.*inject', "web_inject", 8),
    (r'form.*grab|formgrab|POST.*data.*intercept', "form_grabber", 4),
    (r'InternetSetStatusCallback|HttpAddRequestHeaders', "browser_hook", 4),
    (r'bank|paypal|chase|wellsfargo|citibank', "banking_target", 6, ["browser_hook", "web_inject", "form_grabber", "webinject_config", "http_intercept"]),
    (r'set_url|data_before|data_after|data_inject', "webinject_config", 8),
    (r'HttpSendRequestA|HttpSendRequestW', "http_intercept", 4),
    (r'certutil|InstallCert|AddCert', "certificate_install", 6),

    # ══════════════════════════════════════════════════════════════════
    # WIPER / DESTRUCTIVE
    # ══════════════════════════════════════════════════════════════════
    (r'\\\\.\\\\PhysicalDrive', "physical_drive_access", 8),
    (r'MBR|Master Boot Record|\\\\MBR', "mbr_reference", 6),
    (r'InitiateSystemShutdown|ExitWindowsEx|NtShutdownSystem', "forced_shutdown", 4),
    (r'FORMAT\s+[A-Z]:', "format_drive", 6),
    (r'del\s+/[sf]|rmdir\s+/[sq]|Remove-Item.*-Recurse', "mass_delete_command", 8),
    (r'cipher\s+/w:', "secure_overwrite", 8),
    (r'SDelete|sdelete|overwrite', "secure_overwrite", 8),
]
