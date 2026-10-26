"""Authorization policy. One small, deny-by-default function = one place to audit."""


def can_read_record(user, record) -> bool:
    if user is None or record is None:
        return False
    if user["role"] == "admin":
        return True
    return record["owner_id"] == user["id"]   # object-level check, every read
