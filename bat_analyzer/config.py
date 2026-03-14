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
    (r'https?://[^\x00\s]{5,200}', "url"),
    (r'[a-zA-Z0-9-]+\.(com|net|org|io|xyz|top|ru|cn|tk|onion)', "domain"),
    # ── Credentials and tokens ──
    (r'github_pat_[A-Za-z0-9_]{30,}', "github_pat"),
    (r'ghp_[A-Za-z0-9]{36}', "github_token"),
    (r'Bearer\s+[A-Za-z0-9._\-]+', "bearer_token"),
    (r'Authorization:\s*.+', "auth_header"),
    (r'[A-Za-z0-9+/]{40,}={0,2}', "possible_base64"),
    # ── API and C2 ──
    (r'api\.github\.com', "github_api"),
    (r'/repos/[^\x00\s]+', "github_repo_path"),
    (r'/contents/[^\x00\s]+', "github_contents_path"),
    (r'User-Agent:\s*.+', "user_agent"),
    (r'Content-Type:\s*.+', "content_type_header"),
    (r'Accept:\s*.+', "accept_header"),
    # ── OAuth / SSO ──
    (r'login\.microsoftonline\.com', "ms_oauth"),
    (r'oauth2?/authorize', "oauth_endpoint"),
    (r'sso_nonce', "sso_nonce"),
    (r'client_id=[^\x00\s&]+', "client_id"),
    (r'redirect_uri=[^\x00\s&]+', "redirect_uri"),
    (r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', "uuid"),
    # ── File system ──
    (r'C:\\[^\x00]{5,}', "windows_path"),
    (r'%[A-Z]+%', "env_variable"),
    (r'HKLM|HKCU|HKEY_', "registry_key"),
    # ── JSON structures ──
    (r'\{"[a-z_]+":', "json_object"),
    (r'"message":', "json_message_key"),
    (r'"content":', "json_content_key"),
    (r'"branch":', "json_branch_key"),
    # ── Recon ──
    (r'whoami|systeminfo|ipconfig|hostname|tasklist|wmic', "recon_command"),

    # ══════════════════════════════════════════════════════════════════
    # INFOSTEALER TARGETS
    # ══════════════════════════════════════════════════════════════════
    # Browser data paths
    (r'Login Data|Web Data|Cookies|History|Local State|Bookmarks', "browser_data"),
    (r'Google\\\\Chrome|Mozilla\\\\Firefox|Microsoft\\\\Edge|BraveSoftware|Opera', "browser_path"),
    (r'logins\.json|cookies\.sqlite|key[34]\.db|cert[89]\.db|signons\.sqlite', "browser_db"),
    (r'profiles\.ini|places\.sqlite', "firefox_profile"),
    (r'encrypted_key', "browser_masterkey"),
    # Crypto wallets
    (r'wallet\.dat|Electrum|Exodus|Metamask|Atomic Wallet|Coinomi', "crypto_wallet"),
    (r'solana|phantom|trust.wallet|Jaxx|Wasabi', "crypto_wallet"),
    (r'\\\\Ethereum\\\\keystore|\\\\Monero\\\\wallets', "crypto_wallet_path"),
    # Messaging / Discord / Telegram
    (r'Telegram Desktop|\\\\tdata\\\\', "telegram_data"),
    (r'discord(?:canary|ptb)?\\\\Local Storage|leveldb', "discord_data"),
    (r'discordapp\.com/api/webhooks', "discord_webhook"),
    (r'api\.telegram\.org/bot', "telegram_bot_api"),
    (r'Signal\\\\sql\\\\db\.sqlite', "signal_data"),
    # FTP / SSH clients
    (r'FileZilla\\\\recentservers\.xml|FileZilla\\\\sitemanager\.xml', "ftp_credentials"),
    (r'WinSCP\.ini|WinSCP\\\\Sessions', "ftp_credentials"),
    (r'PuTTY\\\\Sessions|SimonTatham\\\\PuTTY', "ssh_credentials"),
    # Email clients
    (r'Thunderbird\\\\Profiles|\\\\Mail\\\\', "email_client"),
    (r'Microsoft\\\\Outlook|Software\\\\Microsoft\\\\Office.*Outlook', "outlook_data"),
    # Gaming platforms
    (r'Steam\\\\config|steamapps|ssfn', "steam_data"),
    (r'\.minecraft\\\\launcher_profiles', "gaming_data"),
    # VPN
    (r'NordVPN|OpenVPN|ProtonVPN|Windscribe', "vpn_credentials"),
    # Password managers
    (r'KeePass|LastPass|1Password|Bitwarden|Dashlane', "password_manager"),
    # Exfiltration indicators
    (r'Content-Disposition.*attachment', "file_upload_header"),
    (r'multipart/form-data', "file_upload_header"),

    # ══════════════════════════════════════════════════════════════════
    # RANSOMWARE
    # ══════════════════════════════════════════════════════════════════
    (r'vssadmin\s+delete\s+shadows', "shadow_copy_delete"),
    (r'wmic\s+shadowcopy\s+delete', "shadow_copy_delete"),
    (r'bcdedit\s+/set\s+\{default\}\s+recoveryenabled\s+no', "disable_recovery"),
    (r'bcdedit\s+/set\s+\{default\}\s+bootstatuspolicy\s+ignoreallfailures', "disable_recovery"),
    (r'wbadmin\s+delete\s+catalog', "delete_backup_catalog"),
    (r'Your files have been encrypted', "ransom_note"),
    (r'All your files are encrypted', "ransom_note"),
    (r'pay.*bitcoin|bitcoin.*wallet|BTC.*address', "ransom_payment"),
    (r'\.encrypted|\.locked|\.crypt|\.enc$', "ransom_extension"),
    (r'DECRYPT|RECOVER|README.*txt|HOW.TO.*DECRYPT', "ransom_note_filename"),
    (r'[13][a-km-zA-HJ-NP-Z1-9]{25,34}', "bitcoin_address"),
    (r'0x[0-9a-fA-F]{40}', "ethereum_address"),
    (r'bc1[a-zA-HJ-NP-Z0-9]{39,59}', "bitcoin_bech32_address"),
    (r'safemode|SafeBoot|bcdedit.*/set.*safeboot', "safemode_boot"),

    # ══════════════════════════════════════════════════════════════════
    # RAT / BACKDOOR
    # ══════════════════════════════════════════════════════════════════
    (r'cmd\.exe|powershell\.exe|pwsh\.exe', "shell_command"),
    (r'\\\\pipe\\\\', "named_pipe"),
    (r'reverse.*shell|bind.*shell|shell.*reverse', "reverse_shell"),
    (r'webcam|camera|capture.*video', "webcam_access"),
    (r'microphone|audio.*record|wave.*in', "audio_record"),
    (r'keylog|key.*log|keyboard.*hook', "keylogger_string"),
    (r'screen.*capture|screenshot|desktop.*capture', "screenshot_string"),
    (r'file.*manager|dir.*listing|upload.*file|download.*file', "file_manager"),
    (r'remote.*desktop|rdp|vnc', "remote_desktop"),
    (r'SOCKS[45]|proxy.*tunnel', "proxy_tunnel"),

    # ══════════════════════════════════════════════════════════════════
    # LOADER / DROPPER
    # ══════════════════════════════════════════════════════════════════
    (r'MZ.*This program', "embedded_pe"),
    (r'ReflectiveLoader|reflective.*dll', "reflective_injection"),
    (r'\\\\Temp\\\\.*\.exe|\\\\Temp\\\\.*\.dll', "temp_drop_path"),
    (r'%TEMP%.*\.exe|%APPDATA%.*\.exe', "temp_drop_path"),
    (r'NtUnmapViewOfSection|ZwUnmapViewOfSection', "process_hollowing_string"),
    (r'RunPE|process.*hollow', "process_hollowing_string"),

    # ══════════════════════════════════════════════════════════════════
    # ROOTKIT
    # ══════════════════════════════════════════════════════════════════
    (r'\\\\.\\\\PhysicalDrive[0-9]', "physical_drive_access"),
    (r'\\\\.\\\\PhysicalMemory', "physical_memory_access"),
    (r'\\\\Device\\\\', "device_path"),
    (r'KeServiceDescriptorTable|SSDT', "ssdt_hook"),
    (r'\\\\SystemRoot\\\\System32\\\\drivers', "driver_path"),
    (r'NtLoadDriver|ZwLoadDriver', "driver_load_string"),
    (r'\\\\Registry\\\\Machine\\\\System.*Services', "driver_registry"),

    # ══════════════════════════════════════════════════════════════════
    # WORM / PROPAGATION
    # ══════════════════════════════════════════════════════════════════
    (r'autorun\.inf', "autorun_inf"),
    (r'\\\\\\\\[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\\\\', "unc_path"),
    (r'net\s+share|net\s+use', "network_share_command"),
    (r'IPC\$|ADMIN\$|C\$', "admin_share"),
    (r'NetShareEnum|NetServerEnum|WNetOpenEnum', "network_enumeration"),
    (r'smtp|MAIL FROM|RCPT TO|EHLO|HELO', "email_worm"),
    (r'USB|removable|GetDriveType', "usb_propagation"),

    # ══════════════════════════════════════════════════════════════════
    # MINER
    # ══════════════════════════════════════════════════════════════════
    (r'stratum\+tcp://|stratum\+ssl://', "mining_stratum"),
    (r'xmrig|cpuminer|cgminer|bfgminer|ethminer|PhoenixMiner', "mining_software"),
    (r'pool\.minexmr|nanopool\.org|2miners\.com|f2pool|hashvault', "mining_pool"),
    (r'4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}', "monero_address"),
    (r'--donate-level|--threads|--cpu-priority|--algo', "miner_cli_args"),
    (r'CryptoNight|RandomX|Ethash|KawPow', "mining_algorithm"),

    # ══════════════════════════════════════════════════════════════════
    # BANKING TROJAN
    # ══════════════════════════════════════════════════════════════════
    (r'inject.*html|webinject|web.*inject', "web_inject"),
    (r'form.*grab|formgrab|POST.*data.*intercept', "form_grabber"),
    (r'InternetSetStatusCallback|HttpAddRequestHeaders', "browser_hook"),
    (r'bank|paypal|chase|wellsfargo|citibank', "banking_target"),
    (r'set_url|data_before|data_after|data_inject', "webinject_config"),
    (r'HttpSendRequestA|HttpSendRequestW', "http_intercept"),
    (r'certutil|InstallCert|AddCert', "certificate_install"),

    # ══════════════════════════════════════════════════════════════════
    # WIPER / DESTRUCTIVE
    # ══════════════════════════════════════════════════════════════════
    (r'\\\\.\\\\PhysicalDrive', "physical_drive_access"),
    (r'MBR|Master Boot Record|\\\\MBR', "mbr_reference"),
    (r'InitiateSystemShutdown|ExitWindowsEx|NtShutdownSystem', "forced_shutdown"),
    (r'FORMAT\s+[A-Z]:', "format_drive"),
    (r'del\s+/[sf]|rmdir\s+/[sq]|Remove-Item.*-Recurse', "mass_delete_command"),
    (r'cipher\s+/w:', "secure_overwrite"),
    (r'SDelete|sdelete|overwrite', "secure_overwrite"),
]
