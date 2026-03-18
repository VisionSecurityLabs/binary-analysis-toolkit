"""PE-specific configuration — suspicious imports."""

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
    "persistence": [
        "RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA",
        "RegCreateKeyExW", "CreateServiceW", "CreateServiceA",
    ],
    "credential_theft": [
        "CredEnumerateA", "CredEnumerateW", "CryptUnprotectData",
        "LsaEnumerateLogonSessions", "SamEnumerateUsersInDomain",
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
}
