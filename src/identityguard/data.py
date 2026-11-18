"""Read and validate the four synthetic CSV input tables."""
from pathlib import Path

import pandas as pd

TABLES = {
    "users": ("user_id", "name", "department", "status", "enabled", "mfa_enabled", "last_login"),
    "roles": ("role_id", "role_name", "department", "privileged"),
    "assignments": ("user_id", "role_id"),
    "signins": ("event_id", "user_id", "timestamp", "success", "country"),
}


class DataValidationError(ValueError):
    """Raised when input CSVs are missing or inconsistent."""


def _bool_column(frame: pd.DataFrame, column: str, table: str) -> None:
    values = frame[column].astype(str).str.lower()
    if not values.isin(["true", "false"]).all():
        raise DataValidationError(f"{table}.{column} must contain only true/false")
    frame[column] = values.eq("true")


def load_data(data_dir: str | Path) -> dict[str, pd.DataFrame]:
    """Load tables, enforce expected columns, types, IDs and foreign keys."""
    folder = Path(data_dir)
    frames = {}
    for table, required in TABLES.items():
        path = folder / f"{table}.csv"
        if not path.is_file():
            raise DataValidationError(f"Missing input file: {path}")
        try:
            frame = pd.read_csv(path, dtype=str, keep_default_na=False)
        except (OSError, pd.errors.ParserError) as exc:
            raise DataValidationError(f"Cannot read {path}: {exc}") from exc
        missing = set(required) - set(frame.columns)
        if missing:
            raise DataValidationError(f"{table}.csv missing columns: {sorted(missing)}")
        if frame[list(required)].eq("").any().any():
            raise DataValidationError(f"{table}.csv contains empty required values")
        frames[table] = frame

    users, roles, assignments, signins = (frames[k] for k in TABLES)
    for frame, col, table in (
        (users, "user_id", "users"),
        (roles, "role_id", "roles"),
        (signins, "event_id", "signins"),
    ):
        if frame[col].duplicated().any():
            raise DataValidationError(f"Duplicate {table}.{col}")
    if assignments.duplicated(subset=["user_id", "role_id"]).any():
        raise DataValidationError("Duplicate user-role assignment")
    for frame, col, valid, label in (
        (assignments, "user_id", users["user_id"], "assignments.user_id"),
        (assignments, "role_id", roles["role_id"], "assignments.role_id"),
        (signins, "user_id", users["user_id"], "signins.user_id"),
    ):
        if not frame[col].isin(valid).all():
            raise DataValidationError(f"Unknown foreign key in {label}")
    for frame, columns, table in (
        (users, ("enabled", "mfa_enabled"), "users"),
        (roles, ("privileged",), "roles"),
        (signins, ("success",), "signins"),
    ):
        for col in columns:
            _bool_column(frame, col, table)
    if not users["status"].isin(["Active", "Terminated", "Leave"]).all():
        raise DataValidationError("users.status must be Active, Terminated or Leave")
    for frame, field, table in ((users, "last_login", "users"), (signins, "timestamp", "signins")):
        try:
            frame[field] = pd.to_datetime(frame[field], errors="raise", utc=True)
        except (ValueError, TypeError) as exc:
            raise DataValidationError(f"Invalid UTC date/time in {table}.{field}") from exc
    return frames
