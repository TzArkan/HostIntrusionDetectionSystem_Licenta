from __future__ import annotations

import ipaddress
import re

_TCP_FLAGS = set("SAFRPU")
_RULE_RE = re.compile(r"^[A-Za-z0-9 _\-\.\(\)]{3,64}$")


def validate_ip(value: str | None, allow_empty: bool = True) -> tuple[bool, str]:
    if value is None:
        return (allow_empty, "" if allow_empty else "IP obligatoriu.")
    text = value.strip()
    if not text:
        return (allow_empty, "" if allow_empty else "IP obligatoriu.")
    try:
        ipaddress.ip_address(text)
        return True, ""
    except ValueError:
        return False, "Format IP invalid. Exemplu valid: 192.168.1.10"


def validate_port(value: str | int | None, allow_empty: bool = True) -> tuple[bool, str]:
    if value is None:
        return (allow_empty, "" if allow_empty else "Port obligatoriu.")
    text = str(value).strip()
    if not text:
        return (allow_empty, "" if allow_empty else "Port obligatoriu.")
    if not text.isdigit():
        return False, "Port invalid. Trebuie numar intre 1 si 65535."
    p = int(text)
    if 1 <= p <= 65535:
        return True, ""
    return False, "Port invalid. Interval permis: 1-65535."


def validate_tcp_flags(value: str | None, allow_empty: bool = True) -> tuple[bool, str]:
    if value is None:
        return (allow_empty, "" if allow_empty else "Flags obligatorii.")
    text = value.strip().upper()
    if not text:
        return (allow_empty, "" if allow_empty else "Flags obligatorii.")
    bad = [c for c in text if c not in _TCP_FLAGS]
    if bad:
        return False, "Flags invalide. Permise doar literele: S, A, F, R, P, U."
    return True, ""


def validate_rule_name(value: str | None) -> tuple[bool, str]:
    text = (value or "").strip()
    if not text:
        return False, "Numele regulii este obligatoriu."
    if not _RULE_RE.match(text):
        return (False, "Nume invalid (3-64 caractere, litere/cifre/spatiu/-_().).",)
    return True, ""

