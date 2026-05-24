from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd

from dylibscope.config.datasets import HLA_DATASET
from dylibscope.config.io import load_jsonl
from dylibscope.config.ios_versions import VERSION_ORDER
from dylibscope.config.versioning import normalize_version_label
from dylibscope.security_analysis.profiles.high_level_analysis import (
    HL_METRICS,
    MIN_COMMON,
    MIN_LIBS_FOR_VERSION,
    MIN_OVERLAP,
    W_TRIAGE,
    HlaTrendReportRow,
    classify,
    format_hla_report,
    raw_risk_row,
)
from dylibscope.security_analysis.utils.common_utils import (
    count_semicolon_list,
    lib_base,
    norm01,
    pct_change,
    pick_col,
    to_int,
)


def load_and_prepare_hla_data(input_path: str | Path) -> pd.DataFrame:
    df = load_jsonl(input_path)

    version_column = pick_col(df, ["ios_version", "version", "ios", "os_version"])
    library_column = pick_col(df, ["file", "library", "lib", "name"])
    sections_column = pick_col(df, ["num_sections"])
    symbols_column = pick_col(df, ["num_symbols"])
    imports_column = pick_col(df, ["imported_functions"])

    df = df.rename(
        columns={
            version_column: "ios_version",
            library_column: "library",
            sections_column: "num_sections",
            symbols_column: "num_symbols",
            imports_column: "imported_functions",
        }
    )

    df["ios_version"] = df["ios_version"].map(normalize_version_label)
    df["library"] = df["library"].map(lib_base)

    df["num_sections"] = df["num_sections"].map(to_int)
    df["num_symbols"] = df["num_symbols"].map(to_int)
    df["import_count"] = df["imported_functions"].map(count_semicolon_list)

    return df.groupby(["ios_version", "library"], as_index=False).agg(
        {
            "num_sections": "max",
            "num_symbols": "max",
            "import_count": "max",
        }
    )


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

        for metric in HL_METRICS:
            version_df[f"{metric}_n"] = norm01(version_df[metric])

        version_df["triage_risk"] = 0.0

        for metric, weight in W_TRIAGE.items():
            version_df["triage_risk"] += weight * version_df[f"{metric}_n"]

        version_df["raw_risk"] = version_df.apply(
            lambda row: raw_risk_row(
                row["num_symbols"],
                row["import_count"],
                row["num_sections"],
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

        per_version[version] = version_df[["library", "raw_risk"] + HL_METRICS].copy()

        summary[version] = {
            "version_risk": version_risk,
            "libs": lib_count,
            "data_quality": data_quality,
        }

    return versions, per_version, summary


def build_hla_trend_rows(
    versions: list[str],
    per_version: dict[str, pd.DataFrame],
    summary: dict[str, dict[str, float | int | str]],
) -> list[HlaTrendReportRow]:
    rows: list[HlaTrendReportRow] = []
    previous_version: str | None = None

    for version in versions:
        version_risk = float(summary[version]["version_risk"])
        data_quality = str(summary[version]["data_quality"])
        libs = int(summary[version]["libs"])

        if previous_version is None:
            rows.append(
                HlaTrendReportRow(
                    ios_version=version,
                    version_risk=version_risk,
                    data_quality=data_quality,
                    release_label="n/a",
                    common=None,
                    overlap=None,
                    delta_raw=None,
                    delta_symbols=None,
                    delta_imports=None,
                    delta_sections=None,
                    libs=libs,
                )
            )
            previous_version = version
            continue

        previous_data_quality = str(summary[previous_version]["data_quality"])

        if previous_data_quality != "ok" or data_quality != "ok":
            rows.append(
                HlaTrendReportRow(
                    ios_version=version,
                    version_risk=version_risk,
                    data_quality=data_quality,
                    release_label="partial_snapshot",
                    common=None,
                    overlap=None,
                    delta_raw=None,
                    delta_symbols=None,
                    delta_imports=None,
                    delta_sections=None,
                    libs=libs,
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
                HlaTrendReportRow(
                    ios_version=version,
                    version_risk=version_risk,
                    data_quality=data_quality,
                    release_label="insufficient_overlap",
                    common=common_libs,
                    overlap=overlap,
                    delta_raw=None,
                    delta_symbols=None,
                    delta_imports=None,
                    delta_sections=None,
                    libs=libs,
                )
            )
            previous_version = version
            continue

        delta_raw = pct_change(
            float(common["raw_risk_prev"].mean()),
            float(common["raw_risk_cur"].mean()),
        )

        delta_symbols = pct_change(
            float(common["num_symbols_prev"].mean()),
            float(common["num_symbols_cur"].mean()),
        )

        delta_imports = pct_change(
            float(common["import_count_prev"].mean()),
            float(common["import_count_cur"].mean()),
        )

        delta_sections = pct_change(
            float(common["num_sections_prev"].mean()),
            float(common["num_sections_cur"].mean()),
        )

        release_label = classify(delta_raw, delta_symbols, delta_imports, delta_sections)

        rows.append(
            HlaTrendReportRow(
                ios_version=version,
                version_risk=version_risk,
                data_quality=data_quality,
                release_label=release_label,
                common=common_libs,
                overlap=overlap,
                delta_raw=delta_raw,
                delta_symbols=delta_symbols,
                delta_imports=delta_imports,
                delta_sections=delta_sections,
                libs=libs,
            )
        )

        previous_version = version

    return rows


def run_hla_trend_analysis(
    input_path: str | Path = HLA_DATASET,
    topk: int = 20,
    print_report: bool = True,
) -> list[HlaTrendReportRow]:
    df = load_and_prepare_hla_data(input_path)
    versions, per_version, summary = compute_version_tables(df, topk)
    rows = build_hla_trend_rows(versions, per_version, summary)

    if print_report:
        print(format_hla_report(rows))

    return rows


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate the high-level DylibScope security trend report.")

    parser.add_argument(
        "--in",
        dest="input_path",
        type=Path,
        default=HLA_DATASET,
        help="Path to the high-level JSONL dataset.",
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
    run_hla_trend_analysis(input_path=args.input_path, topk=args.topk)


if __name__ == "__main__":
    main()
