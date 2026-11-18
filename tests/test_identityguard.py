from datetime import date
import pandas as pd
import pytest
from identityguard.cli import main
from identityguard.config import RiskPolicy
from identityguard.data import DataValidationError, load_data
from identityguard.generate import generate_dataset
from identityguard.scoring import analyze

ANCHOR = date(2026, 11, 18)

@pytest.fixture
def sample(tmp_path):
    generate_dataset(tmp_path, count=60, seed=42, as_of=ANCHOR)
    return load_data(tmp_path)

def test_generator_is_reproducible(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    generate_dataset(a, 60, 15, ANCHOR)
    generate_dataset(b, 60, 15, ANCHOR)
    assert all((a / f"{table}.csv").read_bytes() == (b / f"{table}.csv").read_bytes()
               for table in ("users", "roles", "assignments", "signins"))

def test_all_identities_scored_and_bounded(sample):
    users, findings = analyze(sample, as_of=ANCHOR)
    assert len(users) == 60
    assert users["user_id"].is_unique
    assert users["risk_score"].between(0, 100).all()
    assert not findings.empty
    assert set(findings["user_id"]).issubset(set(users["user_id"]))

def test_terminated_enabled_user_is_flagged(sample):
    users, findings = analyze(sample, as_of=ANCHOR)
    assert "TERMINATED_ACTIVE" in set(findings.loc[findings["user_id"] == "U0001", "rule"])
    assert users.set_index("user_id").loc["U0001", "risk_score"] >= 45

def test_disabled_user_not_flagged_for_access_risks(sample):
    sample["users"].loc[sample["users"]["user_id"] == "U0001", "enabled"] = False
    _, findings = analyze(sample, as_of=ANCHOR)
    rules = set(findings.loc[findings["user_id"] == "U0001", "rule"])
    assert not {"SOD_CONFLICT", "PRIVILEGED_NO_MFA", "TERMINATED_ACTIVE", "DORMANT_ACCOUNT", "STALE_ACCOUNT"} & rules

def test_sod_and_privileged_without_mfa(sample):
    user = "U0002"
    sample["users"].loc[sample["users"]["user_id"] == user, "mfa_enabled"] = False
    sample["assignments"] = pd.concat([sample["assignments"], pd.DataFrame([
        {"user_id": user, "role_id": "ROLE_FIN_CREATE"},
        {"user_id": user, "role_id": "ROLE_FIN_APPROVE"},
    ])], ignore_index=True)
    _, findings = analyze(sample, as_of=ANCHOR)
    rules = set(findings.loc[findings["user_id"] == user, "rule"])
    assert {"SOD_CONFLICT", "PRIVILEGED_NO_MFA"} <= rules

def test_stale_dormant_mutually_exclusive(sample):
    sample["users"].loc[sample["users"]["user_id"] == "U0002", "last_login"] = pd.Timestamp("2026-09-18T12:00:00Z")
    _, findings = analyze(sample, as_of=ANCHOR)
    rules = set(findings.loc[findings["user_id"] == "U0002", "rule"])
    assert "STALE_ACCOUNT" in rules and "DORMANT_ACCOUNT" not in rules
    sample["users"].loc[sample["users"]["user_id"] == "U0002", "last_login"] = pd.Timestamp("2026-07-01T12:00:00Z")
    _, findings = analyze(sample, as_of=ANCHOR)
    rules = set(findings.loc[findings["user_id"] == "U0002", "rule"])
    assert "DORMANT_ACCOUNT" in rules and "STALE_ACCOUNT" not in rules

def test_signin_window_excludes_future_and_old_events(sample):
    user = "U0002"
    sample["signins"] = pd.DataFrame([
        {"event_id": "X1", "user_id": user, "timestamp": pd.Timestamp("2026-11-18T20:00:00Z"), "success": False, "country": "DE"},
        {"event_id": "X2", "user_id": user, "timestamp": pd.Timestamp("2026-11-19T10:00:00Z"), "success": False, "country": "US"},
        {"event_id": "X3", "user_id": user, "timestamp": pd.Timestamp("2026-10-01T10:00:00Z"), "success": False, "country": "US"},
    ])
    users, findings = analyze(sample, as_of=ANCHOR, policy=RiskPolicy(failed_login_threshold=3))
    assert users.set_index("user_id").loc[user, "failed_signins_30d"] == 1
    assert "FOREIGN_LOGIN" not in set(findings["rule"])

def test_invalid_foreign_key_rejected(tmp_path):
    generate_dataset(tmp_path, 10, 42, ANCHOR)
    path = tmp_path / "assignments.csv"
    frame = pd.read_csv(path)
    frame.loc[0, "role_id"] = "NOT_A_REAL_ROLE"
    frame.to_csv(path, index=False)
    with pytest.raises(DataValidationError, match="foreign key"):
        load_data(tmp_path)

def test_cli_creates_reports(tmp_path):
    data, reports = tmp_path / "data", tmp_path / "reports"
    main(["generate", "--data-dir", str(data), "--users", "20", "--as-of", "2026-11-18"])
    main(["analyze", "--data-dir", str(data), "--out-dir", str(reports), "--as-of", "2026-11-18"])
    assert len(pd.read_csv(reports / "user_risks.csv")) == 20
    assert (reports / "audit_findings.csv").stat().st_size > 50

def test_validation_rejects_bad_boolean(tmp_path):
    generate_dataset(tmp_path, 10, 42, ANCHOR)
    path = tmp_path / "users.csv"
    users = pd.read_csv(path, dtype=str)
    users.loc[0, "mfa_enabled"] = "maybe"
    users.to_csv(path, index=False)
    with pytest.raises(DataValidationError, match="true/false"):
        load_data(tmp_path)
