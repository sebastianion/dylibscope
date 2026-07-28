from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from typing import Any

import lief


class UploadedDylibAnalysisError(ValueError):
    """Raised when an uploaded file cannot be analyzed as a Mach-O dynamic library."""


def _safe_len(value: Any) -> int:
    try:
        return len(value or [])
    except TypeError:
        return 0


def _object_name(value: Any) -> str | None:
    if value is None:
        return None
    name = getattr(value, "name", None)
    if callable(name):
        name = name()
    if name:
        return str(name)
    value_text = str(value).strip()
    return value_text or None


def _name_list(values: Iterable[Any]) -> list[str]:
    seen = set()
    names: list[str] = []
    for value in values or []:
        name = _object_name(value)
        if not name or name in seen:
            continue
        seen.add(name)
        names.append(name)
    return names


def _format_version(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, (tuple, list)):
        return ".".join(str(part) for part in value)
    text = str(value).strip()
    return text or None


def _command_name(command: Any) -> str:
    command_type = getattr(command, "command", None)
    name = getattr(command_type, "name", None)
    return str(name or command_type or command.__class__.__name__).upper()


def _extract_deployment_target(binary: Any) -> str | None:
    for attr_name in ("build_version", "version_min"):
        command = getattr(binary, attr_name, None)
        if command is None:
            continue
        for version_attr in ("minos", "version"):
            value = getattr(command, version_attr, None)
            formatted = _format_version(value)
            if formatted:
                return formatted

    for command in getattr(binary, "commands", []) or []:
        command_name = _command_name(command)
        if "BUILD_VERSION" in command_name or "VERSION_MIN" in command_name or "IPHONE" in command_name:
            for version_attr in ("minos", "version"):
                value = getattr(command, version_attr, None)
                formatted = _format_version(value)
                if formatted:
                    return formatted
    return None


def _select_macho_binary(parsed: Any) -> Any:
    module_name = parsed.__class__.__module__.lower()
    class_name = parsed.__class__.__name__.lower()
    if "macho" in module_name and "fat" not in class_name:
        return parsed

    if hasattr(parsed, "at"):
        try:
            candidate = parsed.at(0)
            if candidate is not None:
                return candidate
        except Exception:  # noqa: BLE001 - LIEF exposes version-specific container APIs
            pass

    try:
        for candidate in parsed:
            return candidate
    except TypeError:
        pass

    return parsed


def _require_macho_dylib(binary: Any) -> None:
    module_name = binary.__class__.__module__.lower()
    if "macho" not in module_name:
        raise UploadedDylibAnalysisError("uploaded file is not a Mach-O binary")

    header = getattr(binary, "header", None)
    file_type = getattr(header, "file_type", None)
    file_type_name = getattr(file_type, "name", None) or str(file_type or "")
    if file_type_name and "DYLIB" not in file_type_name.upper():
        raise UploadedDylibAnalysisError("uploaded Mach-O file is not a dynamic library")


def analyze_uploaded_dylib(path: Path) -> dict[str, Any]:
    """Extract DylibScope high-level metrics from one uploaded Mach-O .dylib.

    The uploaded binary is parsed only as data. It is not loaded or executed.
    """
    if not path.exists() or not path.is_file():
        raise UploadedDylibAnalysisError("uploaded file was not written to temporary storage")

    try:
        parsed = lief.parse(str(path))
    except Exception as exc:  # noqa: BLE001 - LIEF can raise several parser-specific exceptions
        raise UploadedDylibAnalysisError(f"LIEF could not parse the uploaded file: {exc}") from exc

    if parsed is None:
        raise UploadedDylibAnalysisError("LIEF could not parse the uploaded file")

    binary = _select_macho_binary(parsed)
    _require_macho_dylib(binary)

    sections = list(getattr(binary, "sections", []) or [])
    symbols = list(getattr(binary, "symbols", []) or [])
    imported_functions = _name_list(getattr(binary, "imported_functions", []) or [])
    exported_functions = _name_list(getattr(binary, "exported_functions", []) or [])
    deployment_target = _extract_deployment_target(binary)

    metrics = {
        "num_sections": _safe_len(sections),
        "num_symbols": _safe_len(symbols),
        "imported_function_count": len(imported_functions),
        "exported_function_count": len(exported_functions),
        "imported_functions": imported_functions,
        "exported_functions": exported_functions,
    }
    if deployment_target:
        metrics["deployment_target"] = deployment_target

    header = getattr(binary, "header", None)
    cpu_type = getattr(header, "cpu_type", None)
    cpu_type_name = getattr(cpu_type, "name", None) or str(cpu_type or "unknown")

    return {
        "format": "Mach-O",
        "architecture": cpu_type_name,
        "deployment_target": deployment_target,
        "metrics": metrics,
    }
