from __future__ import annotations

import os
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import suppress
from pathlib import Path, PurePosixPath
from tempfile import TemporaryDirectory
from typing import Any
from uuid import uuid4

from dylibscope.high_level_analysis.upload_hla import UploadedDylibAnalysisError, analyze_uploaded_dylib
from dylibscope.storage.repository import (
    DatasetConflictError,
    ObservationConflictError,
    create_upload_job,
    create_upload_job_item,
    create_user_hla_upload_observation,
    get_upload_job,
    prepare_user_hla_upload_dataset,
    refresh_upload_job_counts,
    update_upload_job_item_status,
    update_upload_job_status,
)
from dylibscope.storage.schema import connect


class ZipUploadValidationError(ValueError):
    """Raised when an uploaded zip archive is not suitable for batch HLA extraction."""


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


def max_zip_upload_bytes() -> int:
    return _int_env("DYLIBSCOPE_MAX_ZIP_UPLOAD_BYTES", 100_000_000)


def max_zip_dylib_count() -> int:
    return _int_env("DYLIBSCOPE_MAX_ZIP_DYLIB_COUNT", 100)


def max_zip_extracted_bytes() -> int:
    return _int_env("DYLIBSCOPE_MAX_ZIP_EXTRACTED_BYTES", 300_000_000)


def max_upload_file_bytes() -> int:
    return _int_env("DYLIBSCOPE_MAX_UPLOAD_BYTES", 15_000_000)


def upload_parallelism() -> int:
    return max(1, min(_int_env("DYLIBSCOPE_UPLOAD_PARALLELISM", 2), 4))


def _safe_zip_name(name: str) -> str:
    normalized = name.replace("\\", "/")
    path = PurePosixPath(normalized)
    if path.is_absolute() or ".." in path.parts:
        raise ZipUploadValidationError(f"unsafe zip entry path: {name}")
    return normalized


def _library_name_from_zip_entry(name: str) -> str:
    library_name = PurePosixPath(_safe_zip_name(name)).name.strip()
    if not library_name.lower().endswith(".dylib"):
        raise ZipUploadValidationError(f"zip entry is not a .dylib file: {name}")
    return library_name


def inspect_zip_archive(zip_path: Path) -> tuple[list[dict[str, Any]], int]:
    try:
        with zipfile.ZipFile(zip_path) as archive:
            entries: list[dict[str, Any]] = []
            ignored_count = 0
            total_uncompressed = 0
            seen_libraries = set()
            for info in archive.infolist():
                if info.is_dir():
                    continue
                safe_name = _safe_zip_name(info.filename)
                lower_name = safe_name.lower()
                if lower_name.endswith(".zip"):
                    raise ZipUploadValidationError("nested zip files are not supported")
                if not lower_name.endswith(".dylib"):
                    ignored_count += 1
                    continue
                if info.file_size <= 0:
                    raise ZipUploadValidationError(f"empty .dylib file in zip: {safe_name}")
                if info.file_size > max_upload_file_bytes():
                    raise ZipUploadValidationError(
                        f"{safe_name} exceeds the configured per-file limit of {max_upload_file_bytes()} bytes"
                    )
                total_uncompressed += int(info.file_size)
                if total_uncompressed > max_zip_extracted_bytes():
                    raise ZipUploadValidationError(
                        f"zip extracted .dylib size exceeds the configured limit of {max_zip_extracted_bytes()} bytes"
                    )
                library_name = _library_name_from_zip_entry(safe_name)
                canonical_library = library_name.lower()
                if canonical_library in seen_libraries:
                    raise ZipUploadValidationError(
                        f"duplicate .dylib basename in zip: {library_name}. Use unique library basenames per batch."
                    )
                seen_libraries.add(canonical_library)
                entries.append(
                    {
                        "filename": safe_name,
                        "library_name": library_name,
                        "file_size": int(info.file_size),
                    }
                )
    except zipfile.BadZipFile as exc:
        raise ZipUploadValidationError("uploaded file is not a valid zip archive") from exc
    if not entries:
        raise ZipUploadValidationError("zip archive does not contain any .dylib files")
    if len(entries) > max_zip_dylib_count():
        raise ZipUploadValidationError(
            f"zip archive contains {len(entries)} .dylib files, above the configured limit of {max_zip_dylib_count()}"
        )
    return entries, ignored_count


def create_dylib_zip_upload_job(
    conn,
    *,
    owner_user_id: str,
    dataset_name: str,
    ios_version: str,
    target_mode: str,
    conflict_mode: str,
    zip_filename: str,
    zip_byte_count: int,
    zip_path: Path,
) -> dict[str, Any]:
    entries, ignored_count = inspect_zip_archive(zip_path)
    job_id = f"upload_job_{uuid4().hex}"
    create_upload_job(
        conn,
        job_id=job_id,
        owner_user_id=owner_user_id,
        dataset_name=dataset_name,
        ios_version=ios_version,
        target_mode=target_mode,
        conflict_mode=conflict_mode,
        zip_filename=zip_filename,
        zip_byte_count=zip_byte_count,
        total_files=len(entries),
        ignored_count=ignored_count,
    )
    for entry in entries:
        create_upload_job_item(
            conn,
            item_id=f"upload_item_{uuid4().hex}",
            job_id=job_id,
            filename=entry["filename"],
            library_name=entry["library_name"],
        )
    conn.commit()
    return get_upload_job(conn, job_id=job_id, owner_user_id=owner_user_id)


def _extract_member(zip_path: Path, member_name: str, target_path: Path) -> int:
    total_bytes = 0
    with zipfile.ZipFile(zip_path) as archive:
        with archive.open(member_name) as source, target_path.open("wb") as output:
            while True:
                chunk = source.read(1024 * 1024)
                if not chunk:
                    break
                total_bytes += len(chunk)
                if total_bytes > max_upload_file_bytes():
                    raise ZipUploadValidationError(
                        f"{member_name} exceeds the configured per-file limit of {max_upload_file_bytes()} bytes"
                    )
                output.write(chunk)
    if total_bytes == 0:
        raise ZipUploadValidationError(f"{member_name} is empty")
    return total_bytes


def _update_item_status(
    *,
    database_url: str,
    job_id: str,
    owner_user_id: str,
    item_id: str,
    status: str,
    error_message=None,
    observation_id=None,
    refresh_counts: bool = False,
) -> None:
    conn = connect(database_url)
    try:
        update_upload_job_item_status(
            conn,
            item_id=item_id,
            status=status,
            error_message=error_message,
            observation_id=observation_id,
        )
        if refresh_counts:
            refresh_upload_job_counts(conn, job_id=job_id, owner_user_id=owner_user_id)
    finally:
        conn.close()


def _process_one_job_item(
    *,
    database_url: str,
    job_id: str,
    owner_user_id: str,
    dataset_name: str,
    ios_version: str,
    conflict_mode: str,
    zip_path: Path,
    workspace: Path,
    item: dict[str, Any],
) -> None:
    tmp_path = workspace / f"{item['id']}.dylib"
    try:
        _update_item_status(
            database_url=database_url,
            job_id=job_id,
            owner_user_id=owner_user_id,
            item_id=item["id"],
            status="running",
        )

        # File extraction and LIEF parsing can be slow. Do not hold a database connection here.
        _extract_member(zip_path, item["filename"], tmp_path)
        analysis = analyze_uploaded_dylib(tmp_path)

        conn = connect(database_url)
        try:
            observation = create_user_hla_upload_observation(
                conn,
                dataset_name=dataset_name,
                owner_user_id=owner_user_id,
                library_name=item["library_name"],
                ios_version=ios_version,
                metrics=analysis["metrics"],
                original_path=f"uploaded_zip:{item['filename']}",
                target_mode="append_private_dataset",
                conflict_mode=conflict_mode,
            )
            observation_id = observation.get("observation_id") if isinstance(observation, dict) else None
            update_upload_job_item_status(
                conn,
                item_id=item["id"],
                status="processed",
                observation_id=observation_id,
            )
            refresh_upload_job_counts(conn, job_id=job_id, owner_user_id=owner_user_id)
        finally:
            conn.close()
    except (
        UploadedDylibAnalysisError,
        ZipUploadValidationError,
        ObservationConflictError,
        DatasetConflictError,
        ValueError,
        zipfile.BadZipFile,
    ) as exc:
        _update_item_status(
            database_url=database_url,
            job_id=job_id,
            owner_user_id=owner_user_id,
            item_id=item["id"],
            status="failed",
            error_message=str(exc),
            refresh_counts=True,
        )
    except Exception as exc:  # noqa: BLE001
        # Batch jobs should record per-file failures instead of crashing silently.
        _update_item_status(
            database_url=database_url,
            job_id=job_id,
            owner_user_id=owner_user_id,
            item_id=item["id"],
            status="failed",
            error_message=f"unexpected error: {exc}",
            refresh_counts=True,
        )
    finally:
        with suppress(FileNotFoundError):
            tmp_path.unlink()


def process_dylib_zip_upload_job(*, database_url: str, job_id: str, owner_user_id: str, zip_path: str) -> None:
    zip_file_path = Path(zip_path)
    conn = connect(database_url)
    try:
        update_upload_job_status(conn, job_id=job_id, owner_user_id=owner_user_id, status="running")
        job = get_upload_job(conn, job_id=job_id, owner_user_id=owner_user_id)
        prepare_user_hla_upload_dataset(
            conn,
            dataset_name=job["dataset_name"],
            owner_user_id=owner_user_id,
            target_mode=job["target_mode"],
        )
        items = [item for item in job.get("items", []) if item.get("status") == "queued"]
    except Exception as exc:  # noqa: BLE001 - persist job-level failure for polling clients.
        update_upload_job_status(
            conn,
            job_id=job_id,
            owner_user_id=owner_user_id,
            status="failed",
            error_message=str(exc),
        )
        conn.close()
        with suppress(FileNotFoundError):
            zip_file_path.unlink()
        return
    finally:
        with suppress(Exception):
            conn.close()

    try:
        with TemporaryDirectory(prefix="dylibscope-zip-job-") as workspace_dir:
            workspace = Path(workspace_dir)
            with ThreadPoolExecutor(max_workers=upload_parallelism()) as executor:
                futures = [
                    executor.submit(
                        _process_one_job_item,
                        database_url=database_url,
                        job_id=job_id,
                        owner_user_id=owner_user_id,
                        dataset_name=job["dataset_name"],
                        ios_version=job["ios_version"],
                        conflict_mode=job["conflict_mode"],
                        zip_path=zip_file_path,
                        workspace=workspace,
                        item=item,
                    )
                    for item in items
                ]
                for future in as_completed(futures):
                    future.result()
        final_conn = connect(database_url)
        try:
            refresh_upload_job_counts(final_conn, job_id=job_id, owner_user_id=owner_user_id)
            final_job = get_upload_job(final_conn, job_id=job_id, owner_user_id=owner_user_id)
            status = "completed" if int(final_job.get("failed_count") or 0) == 0 else "completed_with_failures"
            update_upload_job_status(final_conn, job_id=job_id, owner_user_id=owner_user_id, status=status)
        finally:
            final_conn.close()
    except Exception as exc:  # noqa: BLE001 - persist job-level failure for polling clients.
        failure_conn = connect(database_url)
        try:
            update_upload_job_status(
                failure_conn,
                job_id=job_id,
                owner_user_id=owner_user_id,
                status="failed",
                error_message=str(exc),
            )
        finally:
            failure_conn.close()
    finally:
        with suppress(FileNotFoundError):
            zip_file_path.unlink()
