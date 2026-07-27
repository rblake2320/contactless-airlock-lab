#!/usr/bin/env python3
"""Independent stdlib canonicalization verifier for Airlock binding vectors.

This tool verifies binding validation, exact canonical bytes, and hashes. It
does not implement or verify approval signatures.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

ORDER = (
    "protocolVersion", "purpose", "challengeId", "subjectId", "accountId",
    "paymentTokenId", "trustedDeviceId", "transactionId", "merchantId",
    "amountMinor", "currency", "issuedAt", "expiresAt", "audience",
)
COMMON_REQUIRED = (
    "protocolVersion", "purpose", "challengeId", "subjectId", "accountId",
    "paymentTokenId", "trustedDeviceId", "issuedAt", "expiresAt", "audience",
)
CURRENCIES = frozenset(("USD", "EUR", "GBP", "CAD", "AUD"))
MAX_SAFE_INTEGER = 9_007_199_254_740_991
CANONICAL_TIMESTAMP = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$"
)


class BindingError(ValueError):
    pass


def _timestamp(value: Any, field: str) -> datetime:
    if not _valid_string(value):
        raise BindingError(f"INVALID_FIELD:{field}")
    if not CANONICAL_TIMESTAMP.fullmatch(value):
        raise BindingError(f"INVALID_TIMESTAMP:{field}")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise BindingError(f"INVALID_TIMESTAMP:{field}") from error


def _valid_string(value: Any) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and not any(0xD800 <= ord(character) <= 0xDFFF for character in value)
    )


def validate(binding: Any) -> None:
    if not isinstance(binding, dict):
        raise BindingError("INVALID_BINDING")
    unknown = sorted(set(binding) - set(ORDER))
    if unknown:
        raise BindingError("UNKNOWN_FIELD:" + ",".join(unknown))
    for field in COMMON_REQUIRED:
        if not _valid_string(binding.get(field)):
            raise BindingError(f"INVALID_FIELD:{field}")
    if binding["protocolVersion"] != "airlock.v1":
        raise BindingError("UNSUPPORTED_VERSION")
    if binding["audience"] != "airlock-issuer":
        raise BindingError("INVALID_AUDIENCE")
    issued = _timestamp(binding["issuedAt"], "issuedAt")
    expires = _timestamp(binding["expiresAt"], "expiresAt")
    if expires <= issued:
        raise BindingError("INVALID_EXPIRY")

    purpose = binding["purpose"]
    if purpose == "confirm-transaction":
        for field in ("transactionId", "merchantId", "currency"):
            if not _valid_string(binding.get(field)):
                raise BindingError(f"INVALID_FIELD:{field}")
        amount = binding.get("amountMinor")
        if isinstance(amount, bool) or not isinstance(amount, (int, float)):
            raise BindingError("INVALID_AMOUNT")
        if (
            not math.isfinite(amount)
            or not float(amount).is_integer()
            or amount <= 0
            or amount > MAX_SAFE_INTEGER
        ):
            raise BindingError("INVALID_AMOUNT")
        if binding["currency"] not in CURRENCIES:
            raise BindingError("UNSUPPORTED_CURRENCY")
    elif purpose == "provision-payment-token":
        if any(
            field in binding
            for field in ("transactionId", "merchantId", "amountMinor", "currency")
        ):
            raise BindingError("TRANSACTION_FIELD_IN_PROVISIONING")
    else:
        raise BindingError("UNSUPPORTED_PURPOSE")


def canonicalize(binding: Any) -> bytes:
    validate(binding)
    ordered = {field: binding[field] for field in ORDER if field in binding}
    # JSON.parse maps all JSON numbers to JavaScript Number. JSON.stringify
    # emits an integer-valued Number such as 1e3 or 1000.0 as `1000`.
    if "amountMinor" in ordered:
        ordered["amountMinor"] = int(ordered["amountMinor"])
    text = json.dumps(
        ordered,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    )
    return text.encode("utf-8")


def verify_vectors(path: Path) -> dict[str, int]:
    document = json.loads(path.read_text(encoding="utf-8"))
    if document.get("schemaVersion") != "airlock.canonical-vectors.v1":
        raise BindingError("UNSUPPORTED_VECTOR_SCHEMA")
    valid_count = 0
    invalid_count = 0
    for vector in document.get("vectors", []):
        if vector.get("valid") is True:
            encoded = canonicalize(vector["binding"])
            if base64.b64encode(encoded).decode("ascii") != vector["canonicalBase64"]:
                raise BindingError(f"BYTE_MISMATCH:{vector.get('id')}")
            if hashlib.sha256(encoded).hexdigest() != vector["sha256"]:
                raise BindingError(f"HASH_MISMATCH:{vector.get('id')}")
            valid_count += 1
        else:
            try:
                canonicalize(vector["binding"])
            except BindingError as error:
                actual_code = str(error).split(":", 1)[0]
                if actual_code != vector.get("errorCode"):
                    raise BindingError(
                        f"ERROR_CODE_MISMATCH:{vector.get('id')}:"
                        f"{actual_code}!={vector.get('errorCode')}"
                    ) from error
                invalid_count += 1
            else:
                raise BindingError(f"EXPECTED_REJECTION:{vector.get('id')}")
    return {"valid": valid_count, "invalid": invalid_count}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--vectors", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = verify_vectors(args.vectors)
    except (BindingError, KeyError, TypeError, json.JSONDecodeError) as error:
        print(json.dumps({"ok": False, "error": str(error)}))
        return 1
    print(json.dumps({"ok": True, **report}, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
