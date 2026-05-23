from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd

from dylibscope.config.datasets import LLA_INPUT
from dylibscope.config.io import load_jsonl
from dylibscope.config.ios_versions import VERSION_ORDER
from dylibscope.config.versioning import normalize_version_label
from dylibscope.security_analysis.utils.common_utils import lib_base, norm01, pct_change, pick_col, to_int
from dylibscope.security_analysis.profiles.low_level_analysis import (
    ALL_METRICS,
    MIN_COMMON,
    MIN_LIBS_FOR_VERSION,
    MIN_OVERLAP,
    RISK_METRICS,
    WEIGHTS,
    TrendReportRow,
    classify,
    format_lla_report,
    raw_risk_lib,
)


def load_and_prepare_lla_data(input_path: str | Path) -> pd.DataFrame:
    df = load_jsonl(input_path)

    version_column = pick_col(df, ["ios_version", "version", "ios", "os_version"])
    library_column = pick_col(df, ["library", "lib", "name", "image_name", "path"])

    df = df.rename(
        columns={
            version_column: "ios_version",
            library_column: "library",
        }
    )

    df["ios_version"] = df["ios_version"].map(normalize_version_label)
    df["library"] = df["library"].map(lib_base)

    for metric in ALL_METRICS:
        if metric not in df.columns:
            df[metric] = 0

        df[metric] = df[metric].map(to_int)

    return df.groupby(["ios_version", "library"], as_index=False).agg({metric: "max" for metric in ALL_METRICS})


def compute_version_tables(
    df: pd.DataFrame,
    topk: int,
) -> tuple[list[str], dict[str, pd.DataFrame], dict[str, dict[str, float | int | str]]]:
    present_versions = set(df["ios_version"].unique())
    versions = [version for version in VERSION_ORDER if version in present_versions]

    per_version: dict[str, pd.DataFrame] = {}
    summary: dict[str, dict[str, float | int | str]] = {}

    for version in versions:
        version_df = df[df["ios_version"] == version].copy()

        for metric in RISK_METRICS:
            version_df[f"{metric}_n"] = norm01(version_df[metric])

        version_df["triage_risk"] = 0.0

        for metric, weight in WEIGHTS.items():
            version_df["triage_risk"] += weight * version_df[f"{metric}_n"]

        version_df["boundary"] = version_df["mach_port_function_count"] + version_df["syscall_function_count"]

        version_df["raw_risk"] = version_df.apply(
            lambda row: raw_risk_lib(
                row["cfg_edge_count"],
                row["allocation_call_count"],
                row["mach_port_function_count"],
                row["syscall_function_count"],
            ),
            axis=1,
        )

        top_libraries = version_df.sort_values(
            "triage_risk",
            ascending=False,
        ).head(topk)

        version_risk = float(top_libraries["triage_risk"].mean()) if len(top_libraries) else 0.0

        lib_count = int(len(version_df))
        data_quality = "ok" if lib_count >= MIN_LIBS_FOR_VERSION else "partial"

        per_version[version] = version_df[["library", "raw_risk"] + ALL_METRICS].copy()

        summary[version] = {
            "version_risk": version_risk,
            "libs": lib_count,
            "data_quality": data_quality,
            "boundary_total": int(version_df["boundary"].sum()),
        }

    return versions, per_version, summary


def build_lla_trend_rows(
    versions: list[str],
    per_version: dict[str, pd.DataFrame],
    summary: dict[str, dict[str, float | int | str]],
) -> list[TrendReportRow]:
    rows: list[TrendReportRow] = []
    previous_version: str | None = None

    for version in versions:
        version_risk = float(summary[version]["version_risk"])
        data_quality = str(summary[version]["data_quality"])
        libs = int(summary[version]["libs"])
        boundary_total = int(summary[version]["boundary_total"])

        if previous_version is None:
            rows.append(
                TrendReportRow(
                    ios_version=version,
                    version_risk=version_risk,
                    data_quality=data_quality,
                    release_label="n/a",
                    common=None,
                    overlap=None,
                    delta_raw=None,
                    delta_cfg=None,
                    delta_alloc=None,
                    delta_boundary=None,
                    libs=libs,
                    boundary_total=boundary_total,
                )
            )
            previous_version = version
            continue

        previous_data_quality = str(summary[previous_version]["data_quality"])

        if previous_data_quality != "ok" or data_quality != "ok":
            rows.append(
                TrendReportRow(
                    ios_version=version,
                    version_risk=version_risk,
                    data_quality=data_quality,
                    release_label="partial_snapshot",
                    common=None,
                    overlap=None,
                    delta_raw=None,
                    delta_cfg=None,
                    delta_alloc=None,
                    delta_boundary=None,
                    libs=libs,
                    boundary_total=boundary_total,
                )
            )
            previous_version = version
            continue

        previous_df = per_version[previous_version]
        current_df = per_version[version]

        common = previous_df.merge(
            current_df,
            on="library",
            how="inner",
            suffixes=("_prev", "_cur"),
        )

        common_libs = int(len(common))
        overlap = (
            common_libs / max(len(previous_df), len(current_df)) if max(len(previous_df), len(current_df)) else 0.0
        )

        if common_libs < MIN_COMMON or overlap < MIN_OVERLAP:
            rows.append(
                TrendReportRow(
                    ios_version=version,
                    version_risk=version_risk,
                    data_quality=data_quality,
                    release_label="insufficient_overlap",
                    common=common_libs,
                    overlap=overlap,
                    delta_raw=None,
                    delta_cfg=None,
                    delta_alloc=None,
                    delta_boundary=None,
                    libs=libs,
                    boundary_total=boundary_total,
                )
            )
            previous_version = version
            continue

        delta_raw = pct_change(
            float(common["raw_risk_prev"].mean()),
            float(common["raw_risk_cur"].mean()),
        )

        delta_cfg = pct_change(
            float(common["cfg_edge_count_prev"].mean()),
            float(common["cfg_edge_count_cur"].mean()),
        )

        delta_alloc = pct_change(
            float(common["allocation_call_count_prev"].mean()),
            float(common["allocation_call_count_cur"].mean()),
        )

        previous_boundary = float(
            (common["mach_port_function_count_prev"] + common["syscall_function_count_prev"]).mean()
        )

        current_boundary = float((common["mach_port_function_count_cur"] + common["syscall_function_count_cur"]).mean())

        delta_boundary = pct_change(previous_boundary, current_boundary)
        release_label = classify(delta_raw, delta_cfg, delta_alloc, delta_boundary)

        rows.append(
            TrendReportRow(
                ios_version=version,
                version_risk=version_risk,
                data_quality=data_quality,
                release_label=release_label,
                common=common_libs,
                overlap=overlap,
                delta_raw=delta_raw,
                delta_cfg=delta_cfg,
                delta_alloc=delta_alloc,
                delta_boundary=delta_boundary,
                libs=libs,
                boundary_total=boundary_total,
            )
        )

        previous_version = version

    return rows


def run_lla_trend_analysis(
    input_path: str | Path = LLA_INPUT,
    topk: int = 20,
    print_report: bool = True,
) -> list[TrendReportRow]:
    df = load_and_prepare_lla_data(input_path)
    versions, per_version, summary = compute_version_tables(df, topk)
    rows = build_lla_trend_rows(versions, per_version, summary)

    if print_report:
        print(format_lla_report(rows))

    return rows


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate the low-level DylibScope security trend report.")

    parser.add_argument(
        "--in",
        dest="input_path",
        type=Path,
        default=LLA_INPUT,
        help="Path to the low-level JSONL dataset.",
    )

    parser.add_argument(
        "--topk",
        type=int,
        default=20,
        help="Number of highest-risk libraries used for version-level risk.",
    )

    return parser.parse_args()


def main() -> None:
    args = parse_args()
    run_lla_trend_analysis(input_path=args.input_path, topk=args.topk)


if __name__ == "__main__":
    main()
