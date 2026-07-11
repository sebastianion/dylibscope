from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional

HLA_NUMERIC_FIELDS = {
    "num_sections",
    "num_symbols",
}

LLA_NUMERIC_FIELDS = {
    "cfg_edge_count",
    "internal_function_count",
    "internal_variable_count",
    "allocation_call_count",
    "syscall_function_count",
    "mach_port_function_count",
}

IOS_VERSION_LABEL_RE = re.compile(
    # Device labels may contain underscores, for example:
    # iPhone_4.0_64bit_10.3.3_14G60
    # Parse from the right: <device>_<ios_release>_<build>.
    r"^(?P<device>.+)_(?P<release>\d+(?:\.\d+){0,2})_(?P<build>[A-Za-z0-9]+)$"
)


@dataclass(frozen=True)
class ParsedIOSVersion:
    """Parsed representation of a DylibScope firmware/iOS label.

    Current datasets use labels such as ``iPhone11,8_12.0_16A366`` and
    ``iPhone_4.0_64bit_10.3.3_14G60``.
    For the API layer we need both the full firmware label and the user-facing
    iOS release such as ``12.0``.
    """

    version_label: str
    device_model: Optional[str]
    ios_release: Optional[str]
    build_number: Optional[str]


def split_symbol_list(value: Any) -> List[str]:
    """Normalize semicolon-separated function lists from the HLA extractor."""
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    text = str(value).strip()
    if not text:
        return []
    return [item.strip() for item in text.split(";") if item.strip()]


def canonicalize_library_name(value: str) -> str:
    """Return a stable case-insensitive library key from a name or path."""
    return os.path.basename(str(value).replace("\\", "/")).strip().lower()


def canonical_library_name(record: Dict[str, Any]) -> str:
    """Return a stable library key shared by HLA and LLA records.

    HLA records use ``file`` and ``path``; LLA records use ``library``.  Both
    forms are matched by lower-casing the basename.
    """
    candidate = record.get("library") or record.get("file") or record.get("path")
    if not candidate:
        raise ValueError("record does not contain library, file, or path")
    canonical = canonicalize_library_name(str(candidate))
    if not canonical:
        raise ValueError("library name is empty after canonicalization")
    return canonical


def display_library_name(record: Dict[str, Any]) -> str:
    candidate = record.get("library") or record.get("file") or record.get("path")
    if not candidate:
        raise ValueError("record does not contain library, file, or path")
    value = os.path.basename(str(candidate).replace("\\", "/")).strip()
    if not value:
        raise ValueError("library display name is empty after normalization")
    return value


def original_path(record: Dict[str, Any]) -> Optional[str]:
    path = record.get("path")
    if path is None:
        return None
    return str(path)


def ios_version_label(record: Dict[str, Any]) -> str:
    value = record.get("ios_version")
    if not value:
        raise ValueError("record does not contain ios_version")
    return str(value).strip()


def parse_ios_version_label(value: str) -> ParsedIOSVersion:
    """Parse labels like ``iPhone11,8_12.0_16A366`` or
    ``iPhone_4.0_64bit_10.3.3_14G60`` when possible.

    If the label does not match the known firmware pattern, keep it as the full
    label and leave the parsed fields empty. This keeps the importer tolerant of
    future dataset formats.
    """
    label = str(value).strip()
    match = IOS_VERSION_LABEL_RE.match(label)
    if not match:
        return ParsedIOSVersion(
            version_label=label,
            device_model=None,
            ios_release=None,
            build_number=None,
        )
    return ParsedIOSVersion(
        version_label=label,
        device_model=match.group("device"),
        ios_release=match.group("release"),
        build_number=match.group("build"),
    )


def normalize_hla_metrics(record: Dict[str, Any]) -> Dict[str, Any]:
    metrics: Dict[str, Any] = {}

    if record.get("deployment_target") is not None:
        metrics["deployment_target"] = str(record.get("deployment_target"))

    for field in HLA_NUMERIC_FIELDS:
        if record.get(field) is not None:
            metrics[field] = int(record[field])

    exported = split_symbol_list(record.get("exported_functions"))
    imported = split_symbol_list(record.get("imported_functions"))

    metrics["exported_function_count"] = len(exported)
    metrics["imported_function_count"] = len(imported)
    metrics["exported_functions"] = exported
    metrics["imported_functions"] = imported

    return metrics


def normalize_lla_metrics(record: Dict[str, Any]) -> Dict[str, Any]:
    metrics: Dict[str, Any] = {}
    for field in LLA_NUMERIC_FIELDS:
        if record.get(field) is not None:
            metrics[field] = int(record[field])
    return metrics


def json_dumps_stable(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def read_jsonl(path: str) -> Iterable[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            text = line.strip()
            if not text:
                continue
            try:
                yield json.loads(text)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSON on line {line_number}: {exc}") from exc
