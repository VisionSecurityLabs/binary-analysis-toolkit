"""PE-specific behavioral rules — rules that check Windows API imports or PE structures.
Grouped roughly by MITRE ATT&CK category."""

from binanalysis.formats.pe.context import PEContext
from binanalysis.rules import Rule


def _check_version_mismatch(ctx: PEContext) -> bool:
    """Generic masquerading: version info claims major vendor but binary has suspicious traits."""
    claimed = ctx.version_info.get("CompanyName", "").lower()
    known_vendors = ["microsoft", "adobe", "google", "mozilla", "apple"]
    if not any(v in claimed for v in known_vendors):
        return False
    return len(ctx.flat_imports) == 0 or any(
        s.get("entropy", 0) > 7.0 for s in ctx.sections
    )


PE_GENERIC_RULES: list[Rule] = [
    # ── Injection ──
    Rule("process_injection", "injection", "high",
         "Classic process injection (VirtualAllocEx -> WriteProcessMemory -> CreateRemoteThread)",
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

    # ── Evasion / Anti-Analysis ──
    Rule("anti_debug_api", "evasion", "medium",
         "Debugger detection via API",
         lambda ctx: ctx.has_import("IsDebuggerPresent", "CheckRemoteDebuggerPresent")),

    Rule("anti_debug_nt", "evasion", "high",
         "Debugger detection via NtQueryInformationProcess",
         lambda ctx: ctx.has_import("NtQueryInformationProcess")),

    Rule("timing_evasion", "evasion", "low",
         "Timing-based sandbox/debugger detection",
         lambda ctx: ctx.has_all_imports("GetTickCount", "QueryPerformanceCounter")),

    Rule("tls_callback", "evasion", "medium",
         "TLS callback may execute code before entry point",
         lambda ctx: hasattr(ctx.pe, "DIRECTORY_ENTRY_TLS") and bool(ctx.pe.DIRECTORY_ENTRY_TLS)),

    Rule("no_import_table", "evasion", "high",
         "No import table — likely packed or manually resolves APIs",
         lambda ctx: len(ctx.flat_imports) == 0),

    # ── Credential Access ──
    Rule("credential_api", "credential_theft", "high",
         "Credential enumeration / DPAPI decryption APIs",
         lambda ctx: ctx.has_import(
             "CredEnumerateA", "CredEnumerateW",
             "CryptUnprotectData",
             "LsaEnumerateLogonSessions",
         )),

    Rule("token_manipulation", "privilege_escalation", "high",
         "Token privilege escalation (OpenProcessToken + AdjustTokenPrivileges)",
         lambda ctx: ctx.has_all_imports("OpenProcessToken", "AdjustTokenPrivileges")
                     and not ctx.is_installer),

    Rule("token_impersonation", "privilege_escalation", "high",
         "Token impersonation / duplication",
         lambda ctx: ctx.has_import("ImpersonateLoggedOnUser", "DuplicateTokenEx")),

    # ── Persistence ──
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

    # ── Execution ──
    Rule("process_creation", "execution", "medium",
         "Creates child processes",
         lambda ctx: ctx.has_import("CreateProcessA", "CreateProcessW", "WinExec")
                     and not ctx.is_installer),

    Rule("shellexecute", "execution", "medium",
         "Launches programs via ShellExecute",
         lambda ctx: ctx.has_import("ShellExecuteA", "ShellExecuteW", "ShellExecuteExW")
                     and not ctx.is_installer),

    Rule("dynamic_api_resolution", "execution", "medium",
         "Dynamically resolves APIs (GetProcAddress + LoadLibrary)",
         lambda ctx: ctx.has_all_imports("GetProcAddress", "LoadLibraryA")
                     or ctx.has_all_imports("GetProcAddress", "LoadLibraryW")),

    # ── Network / C2 ──
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

    # ── Crypto ──
    Rule("crypto_encrypt", "crypto", "low",
         "Uses Windows Crypto API for encryption",
         lambda ctx: ctx.has_import("CryptEncrypt", "BCryptEncrypt")),

    Rule("crypto_decrypt", "crypto", "low",
         "Uses Windows Crypto API for decryption",
         lambda ctx: ctx.has_import("CryptDecrypt", "BCryptDecrypt")),

    Rule("base64_encoding", "encoding", "low",
         "Base64 encodes data via CryptBinaryToString",
         lambda ctx: ctx.has_import("CryptBinaryToStringA", "CryptBinaryToStringW")),

    # ── Masquerading (generic) ──
    Rule("version_mismatch", "masquerading", "high",
         "Version info claims known vendor but binary lacks expected characteristics",
         _check_version_mismatch),
]
