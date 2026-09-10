import json
import pytest
from unittest.mock import patch, AsyncMock

from app.models import Scan, Finding, ArchitectureMetric, HealthScore
from app.ai.evidence_pack import build_evidence_pack
from app.ai.client import AiClient, AiNotConfiguredError, AiValidationError
from app.ai.schemas import DiagnosisResult, PatchResult
from app.config import settings


def test_evidence_pack_capping_and_redaction():
    scan = Scan(
        id="test-scan-1",
        github_url="https://github.com/owner/repo",
        commit_sha="12345678",
        language_stats={"language_counts": {"Python": 10}},
    )

    findings = []
    # Create findings with high-entropy secrets and long snippets
    for i in range(50):
        findings.append(
            Finding(
                id=f"f-{i}",
                scan_id="test-scan-1",
                analyzer="bandit",
                category="security",
                severity="critical" if i < 5 else "low",
                rule_id="bandit:B105",
                file_path=f"src/module_{i}.py",
                start_line=1,
                end_line=25,
                message="Hardcoded password detected",
                redacted_snippet="password = 'my_super_secret_123'\n" * 30,
            )
        )

    pack = build_evidence_pack(scan, findings, [], None)
    pack_json = json.dumps(pack)

    # Size must be strictly under the 64KB cap
    assert len(pack_json.encode("utf-8")) <= settings.MAX_EVIDENCE_PACK_KB * 1024
    # Secrets must be redacted
    assert "my_super_secret_123" not in pack_json
    assert "[REDACTED_SECRET]" in pack_json


@pytest.mark.asyncio
async def test_ai_client_not_configured():
    client = AiClient()
    client.api_key = None
    assert not client.is_configured()

    with pytest.raises(AiNotConfiguredError):
        await client.generate_diagnosis({"scan_id": "test"})


@pytest.mark.asyncio
async def test_ai_client_valid_diagnosis():
    client = AiClient()
    client.api_key = "test-key"

    valid_response = json.dumps({
        "summary": "Overall healthy codebase with 1 critical command injection.",
        "diagnoses": [
            {
                "diagnosis": "Command Injection in CLI",
                "why_it_matters": "Untrusted input passed to shell=True allows arbitrary execution.",
                "impact": "Remote code execution risk.",
                "recommended_action": "Use subprocess.run with argument array and shell=False.",
                "priority": "critical",
                "confidence": 0.98,
                "evidence_sufficient": True,
                "related_finding_ids": ["f-1"]
            }
        ]
    })

    with patch.object(client, "_post_chat_completion", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = valid_response
        result, raw = await client.generate_diagnosis({"scan_id": "test"})

    assert isinstance(result, DiagnosisResult)
    assert len(result.diagnoses) == 1
    assert result.diagnoses[0].priority == "critical"
    assert result.diagnoses[0].confidence == 0.98


@pytest.mark.asyncio
async def test_ai_client_validation_retry():
    client = AiClient()
    client.api_key = "test-key"

    invalid_first = "{ broken json"
    valid_second = json.dumps({
        "summary": "Cleaned assessment",
        "diagnoses": [
            {
                "diagnosis": "Unused imports",
                "why_it_matters": "Dead code increases cognitive overhead.",
                "impact": "Code bloat.",
                "recommended_action": "Remove unused imports.",
                "priority": "low",
                "confidence": 0.95,
                "evidence_sufficient": True,
                "related_finding_ids": ["f-2"]
            }
        ]
    })

    with patch.object(client, "_post_chat_completion", new_callable=AsyncMock) as mock_post:
        # First call returns invalid, second call returns valid
        mock_post.side_effect = [invalid_first, valid_second]
        result, raw = await client.generate_diagnosis({"scan_id": "test"})

    assert isinstance(result, DiagnosisResult)
    assert mock_post.call_count == 2
    assert result.diagnoses[0].priority == "low"
