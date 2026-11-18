"""Risk rules, scoring weights, and static role definitions."""
from dataclasses import dataclass


@dataclass(frozen=True)
class RiskPolicy:
    inactive_days: int = 90
    stale_days: int = 45
    recent_login_window_days: int = 30
    failed_login_threshold: int = 5
    high_risk_threshold: int = 60
    medium_risk_threshold: int = 30


WEIGHTS = {
    "TERMINATED_ACTIVE": 45,
    "PRIVILEGED_NO_MFA": 30,
    "SOD_CONFLICT": 35,
    "STALE_ACCOUNT": 20,
    "DORMANT_ACCOUNT": 15,
    "LOGIN_FAILURE_SPIKE": 15,
    "FOREIGN_LOGIN": 10,
}

SEVERITIES = {
    "TERMINATED_ACTIVE": "Critical",
    "PRIVILEGED_NO_MFA": "High",
    "SOD_CONFLICT": "High",
    "STALE_ACCOUNT": "Medium",
    "DORMANT_ACCOUNT": "Medium",
    "LOGIN_FAILURE_SPIKE": "Medium",
    "FOREIGN_LOGIN": "Low",
}

ROLE_DEFINITIONS = [
    ("ROLE_VIEW_REPORTS", "Reports Viewer", "Analytics", False),
    ("ROLE_DATA_EXPORT", "Data Export", "Analytics", False),
    ("ROLE_HR_READ", "HR Reader", "HR", False),
    ("ROLE_HR_WRITE", "HR Editor", "HR", True),
    ("ROLE_FIN_CREATE", "Payment Creator", "Finance", True),
    ("ROLE_FIN_APPROVE", "Payment Approver", "Finance", True),
    ("ROLE_IAM_PROVISION", "Identity Provisioner", "IT", True),
    ("ROLE_IAM_AUDIT", "Identity Auditor", "IT", True),
    ("ROLE_GLOBAL_ADMIN", "Global Admin", "IT", True),
    ("ROLE_HELPDESK", "Helpdesk", "IT", False),
    ("ROLE_SALES_CRM", "CRM Editor", "Sales", False),
    ("ROLE_MARKETING", "Campaign Manager", "Marketing", False),
]

SOD_PAIRS = (
    ("ROLE_FIN_CREATE", "ROLE_FIN_APPROVE", "Create and approve payments"),
    ("ROLE_IAM_PROVISION", "ROLE_IAM_AUDIT", "Provision identities and audit changes"),
)
