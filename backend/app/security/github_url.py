import re
import ipaddress
from urllib.parse import urlparse


ALLOWED_HOSTS = {"github.com", "www.github.com"}
REPO_PATH_PATTERN = re.compile(r"^/([a-zA-Z0-9_.-]+)/([a-zA-Z0-9_.-]+?)(?:\.git)?/?$")


class InvalidGitHubURLError(ValueError):
    """Raised when a provided repository URL fails security validation."""
    pass


def validate_and_normalize_github_url(url: str) -> str:
    """
    Validate and normalize a GitHub repository URL against SSRF, injection, and invalid schemes.

    Rules:
    - Must be HTTPS protocol.
    - Host must strictly be github.com or www.github.com.
    - No userinfo (user:pass@).
    - No custom ports.
    - Must not resolve to IP addresses or localhost.
    - Path must match /owner/repo[.git].
    - Returns normalized canonical URL: https://github.com/owner/repo
    """
    if not url or not isinstance(url, str):
        raise InvalidGitHubURLError("GitHub URL cannot be empty.")

    url = url.strip()

    try:
        parsed = urlparse(url)
    except Exception as e:
        raise InvalidGitHubURLError(f"Malformed URL: {e}")

    # Scheme check
    if parsed.scheme.lower() != "https":
        raise InvalidGitHubURLError("Only HTTPS URLs are permitted.")

    # Userinfo check
    if parsed.username or parsed.password:
        raise InvalidGitHubURLError("URLs containing userinfo/credentials are prohibited.")

    # Port check
    if parsed.port and parsed.port != 443:
        raise InvalidGitHubURLError("Custom ports are not permitted.")

    # Host check
    hostname = (parsed.hostname or "").lower()
    if not hostname:
        raise InvalidGitHubURLError("Missing hostname in repository URL.")

    # Check for IP address tricks (IPv4, IPv6, localhost, integer representations)
    if hostname == "localhost" or hostname.endswith(".local") or hostname.endswith(".internal"):
        raise InvalidGitHubURLError("Local and internal hostnames are prohibited.")

    try:
        ip = ipaddress.ip_address(hostname)
        # Any direct IP address is rejected
        raise InvalidGitHubURLError(f"Direct IP addresses are prohibited ({ip}).")
    except ValueError:
        # Not a raw IP literal, proceed to host allowlist check
        pass

    if hostname not in ALLOWED_HOSTS:
        raise InvalidGitHubURLError(f"Host '{hostname}' is not permitted. Only github.com is allowed.")

    # Path validation: /owner/repo
    path = parsed.path
    match = REPO_PATH_PATTERN.match(path)
    if not match:
        raise InvalidGitHubURLError("Invalid repository path format. Expected format: https://github.com/owner/repo")

    owner, repo = match.group(1), match.group(2)

    # Security check on owner/repo tokens: reject directory traversal attempts
    if owner in {".", ".."} or repo in {".", ".."}:
        raise InvalidGitHubURLError("Invalid owner or repository name.")

    # Canonical HTTPS URL
    normalized = f"https://github.com/{owner}/{repo}"
    return normalized
