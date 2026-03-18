"""Static configuration — format-agnostic string patterns."""

SUSPICIOUS_STRING_PATTERNS = [
    # URLs and domains
    (r'https?://[^\x00\s]{5,200}', "url"),
    (r'[a-zA-Z0-9-]+\.(com|net|org|io|xyz|top|ru|cn|tk|onion)', "domain"),
    # Credentials and tokens
    (r'github_pat_[A-Za-z0-9_]{30,}', "github_pat"),
    (r'ghp_[A-Za-z0-9]{36}', "github_token"),
    (r'Bearer\s+[A-Za-z0-9._\-]+', "bearer_token"),
    (r'Authorization:\s*.+', "auth_header"),
    (r'[A-Za-z0-9+/]{40,}={0,2}', "possible_base64"),
    # API and C2
    (r'api\.github\.com', "github_api"),
    (r'/repos/[^\x00\s]+', "github_repo_path"),
    (r'/contents/[^\x00\s]+', "github_contents_path"),
    (r'User-Agent:\s*.+', "user_agent"),
    (r'Content-Type:\s*.+', "content_type_header"),
    (r'Accept:\s*.+', "accept_header"),
    # OAuth / SSO
    (r'login\.microsoftonline\.com', "ms_oauth"),
    (r'oauth2?/authorize', "oauth_endpoint"),
    (r'sso_nonce', "sso_nonce"),
    (r'client_id=[^\x00\s&]+', "client_id"),
    (r'redirect_uri=[^\x00\s&]+', "redirect_uri"),
    (r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', "uuid"),
    # File system
    (r'C:\\[^\x00]{5,}', "windows_path"),
    (r'%[A-Z]+%', "env_variable"),
    (r'HKLM|HKCU|HKEY_', "registry_key"),
    # JSON structures
    (r'\{"[a-z_]+":', "json_object"),
    (r'"message":', "json_message_key"),
    (r'"content":', "json_content_key"),
    (r'"branch":', "json_branch_key"),
    # Recon
    (r'whoami|systeminfo|ipconfig|hostname|tasklist|wmic', "recon_command"),
]
