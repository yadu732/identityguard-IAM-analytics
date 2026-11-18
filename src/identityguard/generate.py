"""Deterministic, fully fictional IAM data. No production identities."""
import csv
import random
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from identityguard.config import ROLE_DEFINITIONS

DEPARTMENTS = ("IT", "Finance", "HR", "Sales", "Marketing", "Analytics")
NAMES_FIRST = ("Alex", "Sam", "Jordan", "Taylor", "Casey", "Morgan", "Avery", "Jamie", "Robin", "Riley")
NAMES_LAST = ("Stone", "Patel", "Kim", "Meyer", "Smith", "Roy", "Wong", "Bauer", "Diaz", "Khan")


def _write_csv(path: Path, columns: list[str], records: list[dict]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        writer.writerows(records)


def generate_dataset(directory: str | Path, count: int = 300, seed: int = 42,
                     as_of: date | None = None) -> dict[str, int]:
    """Create the four matching CSVs. The same seed/date yields identical contents."""
    if count < 10:
        raise ValueError("count must be at least 10")
    rng = random.Random(seed)
    anchor = as_of or date.today()
    out = Path(directory)
    out.mkdir(parents=True, exist_ok=True)
    users, assignments, signins = [], [], []
    roles = [dict(zip(("role_id", "role_name", "department", "privileged"), role))
             for role in ROLE_DEFINITIONS]
    for role in roles:
        role["privileged"] = str(role["privileged"]).lower()
    by_department = {dept: [r["role_id"] for r in roles if r["department"] == dept]
                     for dept in DEPARTMENTS}
    event_number = 1
    for i in range(count):
        user_id = f"U{i+1:04d}"
        dept = DEPARTMENTS[i % len(DEPARTMENTS)]
        status = "Terminated" if i % 29 == 0 else "Leave" if i % 37 == 0 else "Active"
        enabled = status != "Terminated" or i % 2 == 0
        mfa = i % 13 != 0 and rng.random() > .08
        days_since = rng.randint(95, 250) if i % 11 == 0 else rng.randint(0, 75)
        last = datetime.combine(anchor - timedelta(days=days_since),
                                datetime.min.time(), tzinfo=timezone.utc) + timedelta(hours=12)
        users.append({"user_id": user_id,
                      "name": f"{NAMES_FIRST[i % len(NAMES_FIRST)]} {NAMES_LAST[(i//10) % len(NAMES_LAST)]} {i+1}",
                      "department": dept, "status": status,
                      "enabled": str(enabled).lower(), "mfa_enabled": str(mfa).lower(),
                      "last_login": last.isoformat()})
        selected = {rng.choice(by_department[dept]), "ROLE_VIEW_REPORTS"}
        if i % 9 == 0:
            selected.add("ROLE_GLOBAL_ADMIN")
        if i % 17 == 0:
            selected.update(["ROLE_FIN_CREATE", "ROLE_FIN_APPROVE"])
        if i % 23 == 0:
            selected.update(["ROLE_IAM_PROVISION", "ROLE_IAM_AUDIT"])
        for role_id in sorted(selected):
            assignments.append({"user_id": user_id, "role_id": role_id})
        number_events = rng.randint(2, 8)
        for e in range(number_events):
            days_ago = rng.randint(0, 29)
            timestamp = datetime.combine(anchor - timedelta(days=days_ago),
                                         datetime.min.time(), tzinfo=timezone.utc) + timedelta(hours=rng.randint(0, 23))
            bad_login = i % 19 == 0 or rng.random() < .1
            signins.append({"event_id": f"E{event_number:06d}", "user_id": user_id,
                            "timestamp": timestamp.isoformat(),
                            "success": str(not bad_login).lower(),
                            "country": "Unknown" if i % 31 == 0 and e == 0 else "DE"})
            event_number += 1
    _write_csv(out / "users.csv", list(users[0]), users)
    _write_csv(out / "roles.csv", list(roles[0]), roles)
    _write_csv(out / "assignments.csv", list(assignments[0]), assignments)
    _write_csv(out / "signins.csv", list(signins[0]), signins)
    return {"users": len(users), "roles": len(roles), "assignments": len(assignments), "signins": len(signins)}
