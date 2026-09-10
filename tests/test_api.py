import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch

from app.main import app
from app.models import Scan, Finding, HealthScore, ArchitectureMetric
from app.db import get_db, Base, engine, SessionLocal


@pytest.fixture
def client():
    # Setup test DB tables
    Base.metadata.create_all(bind=engine)
    with TestClient(app) as c:
        yield c


def test_health_endpoint(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_create_scan_valid_url(client):
    with patch("app.api.routes_scans.enqueue_scan") as mock_enqueue:
        response = client.post("/api/scans", json={"github_url": "https://github.com/octocat/Hello-World"})
        assert response.status_code == 202
        data = response.json()
        assert "scan_id" in data
        assert len(data["scan_id"]) > 0


def test_create_scan_invalid_url(client):
    # Localhost attempt
    response = client.post("/api/scans", json={"github_url": "https://localhost/repo"})
    assert response.status_code == 400
    assert "prohibited" in response.json()["detail"].lower() or "not permitted" in response.json()["detail"].lower()

    # Non-github host
    response = client.post("/api/scans", json={"github_url": "https://gitlab.com/user/repo"})
    assert response.status_code == 400


def test_get_scan_and_findings(client):
    db = SessionLocal()
    scan = Scan(
        github_url="https://github.com/octocat/Hello-World",
        status="succeeded",
        commit_sha="abc12345",
        language_stats={"total_files": 5, "python_files": 2},
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    f1 = Finding(
        scan_id=scan.id,
        analyzer="bandit",
        category="security",
        severity="high",
        rule_id="bandit:B602",
        file_path="main.py",
        start_line=10,
        end_line=10,
        message="shell=True used",
    )
    f2 = Finding(
        scan_id=scan.id,
        analyzer="ruff",
        category="dead_code",
        severity="low",
        rule_id="ruff:F401",
        file_path="main.py",
        start_line=1,
        end_line=1,
        message="unused import os",
    )
    db.add_all([f1, f2])

    score = HealthScore(
        scan_id=scan.id,
        security=92.0,
        architecture=100.0,
        maintainability=99.0,
        performance=100.0,
        code_quality=100.0,
        dependencies=100.0,
        overall=98.0,
        breakdown={"security": {"final_score": 92.0}},
    )
    db.add(score)
    db.commit()
    scan_id = scan.id
    db.close()

    # 1. Get scan status
    res = client.get(f"/api/scans/{scan_id}")
    assert res.status_code == 200
    assert res.json()["status"] == "succeeded"
    assert res.json()["commit_sha"] == "abc12345"

    # 2. Get findings
    res = client.get(f"/api/scans/{scan_id}/findings")
    assert res.status_code == 200
    assert len(res.json()) == 2

    # Filter findings by category
    res = client.get(f"/api/scans/{scan_id}/findings?category=security")
    assert res.status_code == 200
    assert len(res.json()) == 1
    assert res.json()[0]["category"] == "security"

    # 3. Get score
    res = client.get(f"/api/scans/{scan_id}/score")
    assert res.status_code == 200
    data = res.json()
    assert data["security"] == 92.0
    assert data["overall"] == 98.0
    assert "breakdown" in data
