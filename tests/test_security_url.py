import pytest
from app.security.github_url import validate_and_normalize_github_url, InvalidGitHubURLError


def test_valid_github_urls():
    assert validate_and_normalize_github_url("https://github.com/owner/repo") == "https://github.com/owner/repo"
    assert validate_and_normalize_github_url("https://github.com/owner/repo.git") == "https://github.com/owner/repo"
    assert validate_and_normalize_github_url("https://www.github.com/owner/repo") == "https://github.com/owner/repo"
    assert validate_and_normalize_github_url("https://github.com/owner-name/repo_name.v2") == "https://github.com/owner-name/repo_name.v2"


def test_reject_non_https():
    with pytest.raises(InvalidGitHubURLError, match="Only HTTPS URLs are permitted"):
        validate_and_normalize_github_url("http://github.com/owner/repo")

    with pytest.raises(InvalidGitHubURLError, match="Only HTTPS URLs are permitted"):
        validate_and_normalize_github_url("git://github.com/owner/repo")

    with pytest.raises(InvalidGitHubURLError, match="Only HTTPS URLs are permitted"):
        validate_and_normalize_github_url("file:///etc/passwd")


def test_reject_ssrf_and_ip_literals():
    with pytest.raises(InvalidGitHubURLError):
        validate_and_normalize_github_url("https://localhost/owner/repo")

    with pytest.raises(InvalidGitHubURLError):
        validate_and_normalize_github_url("https://127.0.0.1/owner/repo")

    with pytest.raises(InvalidGitHubURLError):
        validate_and_normalize_github_url("https://169.254.169.254/latest/meta-data")

    with pytest.raises(InvalidGitHubURLError):
        validate_and_normalize_github_url("https://10.0.0.1/owner/repo")

    with pytest.raises(InvalidGitHubURLError):
        validate_and_normalize_github_url("https://0.0.0.0/owner/repo")


def test_reject_userinfo_and_ports():
    with pytest.raises(InvalidGitHubURLError, match="userinfo"):
        validate_and_normalize_github_url("https://user:password@github.com/owner/repo")

    with pytest.raises(InvalidGitHubURLError, match="Custom ports"):
        validate_and_normalize_github_url("https://github.com:8080/owner/repo")


def test_reject_unauthorized_hosts():
    with pytest.raises(InvalidGitHubURLError, match="Host 'gitlab.com' is not permitted"):
        validate_and_normalize_github_url("https://gitlab.com/owner/repo")

    with pytest.raises(InvalidGitHubURLError):
        validate_and_normalize_github_url("https://github.evil.com/owner/repo")


def test_reject_malformed_paths_and_traversal():
    with pytest.raises(InvalidGitHubURLError):
        validate_and_normalize_github_url("https://github.com/owner")

    with pytest.raises(InvalidGitHubURLError):
        validate_and_normalize_github_url("https://github.com/owner/repo/extra/path")

    with pytest.raises(InvalidGitHubURLError):
        validate_and_normalize_github_url("https://github.com/../repo")
