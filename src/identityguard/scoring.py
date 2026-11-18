"""Transparent, rule-based IAM scoring. Findings are review signals, not proof of abuse."""
from datetime import date, datetime, time, timedelta, timezone

import pandas as pd

from identityguard.config import RiskPolicy, SEVERITIES, SOD_PAIRS, WEIGHTS


def analyze(data: dict[str, pd.DataFrame], as_of: date | None = None,
            policy: RiskPolicy | None = None) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Return one scored row per identity and one row per policy finding.

    All scores are additive, capped at 100. No probabilities or ML predictions.
    Authentication events after the as_of end-of-day boundary are excluded.
    """
    policy = policy or RiskPolicy()
    anchor = as_of or date.today()
    end = datetime.combine(anchor, time.max, tzinfo=timezone.utc)
    begin = datetime.combine(anchor - timedelta(days=policy.recent_login_window_days - 1),
                             time.min, tzinfo=timezone.utc)
    users, roles, assignments, signins = (data[k] for k in ("users", "roles", "assignments", "signins"))
    privileged = set(roles.loc[roles["privileged"], "role_id"])
    user_roles: dict[str, set[str]] = assignments.groupby("user_id")["role_id"].agg(set).to_dict()
    recent = signins[(signins["timestamp"] >= begin) & (signins["timestamp"] <= end)]
    failed = recent[~recent["success"]].groupby("user_id").size().to_dict()
    foreign = recent[recent["country"] != "DE"].groupby("user_id").size().to_dict()
    rows, findings = [], []
    for u in users.itertuples(index=False):
        role_set = user_roles.get(u.user_id, set())
        is_privileged = bool(role_set & privileged)
        days_inactive = max((end.date() - u.last_login.date()).days, 0)
        local = []

        def flag(code: str, evidence: str) -> None:
            local.append({"user_id": u.user_id, "name": u.name,
                          "rule": code, "severity": SEVERITIES[code],
                          "points": WEIGHTS[code], "evidence": evidence,
                          "recommendation": RECOMMENDATIONS[code]})

        if u.status == "Terminated" and u.enabled:
            flag("TERMINATED_ACTIVE", "Terminated identity remains enabled")
        if u.enabled and is_privileged and not u.mfa_enabled:
            flag("PRIVILEGED_NO_MFA", "Privileged role assigned without MFA")
        if u.enabled:
            for first, second, reason in SOD_PAIRS:
                if {first, second}.issubset(role_set):
                    flag("SOD_CONFLICT", f"{reason}: {first} + {second}")
            if days_inactive > policy.inactive_days:
                flag("DORMANT_ACCOUNT", f"Last login {days_inactive} days ago")
            elif days_inactive > policy.stale_days:
                flag("STALE_ACCOUNT", f"Last login {days_inactive} days ago")
        if failed.get(u.user_id, 0) >= policy.failed_login_threshold:
            flag("LOGIN_FAILURE_SPIKE", f"{failed[u.user_id]} failed events in latest {policy.recent_login_window_days} days")
        if foreign.get(u.user_id, 0) > 0:
            flag("FOREIGN_LOGIN", f"{foreign[u.user_id]} sign-ins outside expected DE country")
        score = min(100, sum(item["points"] for item in local))
        risk_level = ("High" if score >= policy.high_risk_threshold else
                      "Medium" if score >= policy.medium_risk_threshold else "Low")
        rows.append({"user_id": u.user_id, "name": u.name, "department": u.department,
                     "status": u.status, "enabled": u.enabled, "mfa_enabled": u.mfa_enabled,
                     "last_login": u.last_login.date().isoformat(), "days_inactive": days_inactive,
                     "role_count": len(role_set), "privileged": is_privileged,
                     "failed_signins_30d": failed.get(u.user_id, 0),
                     "risk_score": score, "risk_level": risk_level,
                     "finding_count": len(local)})
        findings.extend(local)
    scored = pd.DataFrame(rows).sort_values(["risk_score", "user_id"], ascending=[False, True]).reset_index(drop=True)
    findings_df = pd.DataFrame(findings, columns=["user_id", "name", "rule", "severity", "points", "evidence", "recommendation"])
    return scored, findings_df


RECOMMENDATIONS = {
    "TERMINATED_ACTIVE": "Verify termination and promptly disable the identity after owner approval.",
    "PRIVILEGED_NO_MFA": "Enforce an approved phishing-resistant MFA method for privileged access.",
    "SOD_CONFLICT": "Review incompatible role assignments with the business owner.",
    "STALE_ACCOUNT": "Confirm the account is needed and schedule an access review.",
    "DORMANT_ACCOUNT": "Confirm ownership; disable unused access through approved workflow.",
    "LOGIN_FAILURE_SPIKE": "Investigate sign-in events and verify legitimate user activity.",
    "FOREIGN_LOGIN": "Verify sign-in geography and account activity; travel/VPN may explain it.",
}
