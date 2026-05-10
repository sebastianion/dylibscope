from __future__ import annotations

import argparse
import math
from typing import Dict, List

import pandas as pd
from dylibscope.config.ios_versions import VERSION_ORDER
from dylibscope.config.io import load_jsonl
from dylibscope.config.versioning import normalize_version_label

from dylibscope.security_analysis.utils.common_utils import (
    pick_col,
    lib_base,
    to_int,
    count_semicolon_list,
    norm01,
    pct_change,
)

from dylibscope.security_analysis.utils.hla_utils import *


def raw_risk_row(num_symbols: float, import_count: float, num_sections: float) -> float:
    return (
        W_RAW["num_symbols"] * math.log1p(max(num_symbols, 0.0))
        + W_RAW["import_count"] * math.log1p(max(import_count, 0.0))
        + W_RAW["num_sections"] * math.log1p(max(num_sections, 0.0))
    )


def classify(d_raw: float, d_syms: float, d_imps: float, d_secs: float) -> str:
    up = sum([d_syms >= THR_SYMS, d_imps >= THR_IMPS, d_secs >= THR_SECS])
    down = sum([d_syms <= -THR_SYMS, d_imps <= -THR_IMPS, d_secs <= -THR_SECS])

    expanding_a = (d_raw >= THR_RAW_RISK) and (up >= 1)
    hardening_a = (d_raw <= -THR_RAW_RISK) and (down >= 1)

    expanding_b = (up >= 2)
    hardening_b = (down >= 2)

    if hardening_a or hardening_b:
        return "hardening"
    if expanding_a or expanding_b:
        return "expanding"
    return "stable"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="in_path", required=True)
    ap.add_argument("--topk", type=int, default=20)
    args = ap.parse_args()

    df = load_jsonl(args.in_path)
    vcol = pick_col(df, ["ios_version", "version", "ios", "os_version"])
    fcol = pick_col(df, ["file", "library", "lib", "name"])
    scol = pick_col(df, ["num_sections"])
    ycol = pick_col(df, ["num_symbols"])
    impcol = pick_col(df, ["imported_functions"])

    df = df.rename(columns={
        vcol: "ios_version",
        fcol: "library",
        scol: "num_sections",
        ycol: "num_symbols",
        impcol: "imported_functions",
    })

    df["ios_version"] = df["ios_version"].map(normalize_version_label)
    df["library"] = df["library"].map(lib_base)

    df["num_sections"] = df["num_sections"].map(to_int)
    df["num_symbols"] = df["num_symbols"].map(to_int)
    df["import_count"] = df["imported_functions"].map(count_semicolon_list)

    df = df.groupby(["ios_version", "library"], as_index=False).agg({
        "num_sections": "max",
        "num_symbols": "max",
        "import_count": "max",
    })

    present_versions = set(df["ios_version"].unique())
    versions = [v for v in VERSION_ORDER if v in present_versions]

    per_version: Dict[str, pd.DataFrame] = {}
    summary: Dict[str, Dict[str, float]] = {}

    for v in versions:
        dv = df[df["ios_version"] == v].copy()
        for m in HL_METRICS:
            dv[m + "_n"] = norm01(dv[m])

        dv["triage_risk"] = (
            W_TRIAGE["num_symbols"] * dv["num_symbols_n"]
            + W_TRIAGE["import_count"] * dv["import_count_n"]
            + W_TRIAGE["num_sections"] * dv["num_sections_n"]
        )

        dv["raw_risk"] = dv.apply(lambda r: raw_risk_row(r["num_symbols"], r["import_count"], r["num_sections"]), axis=1)

        topk = dv.sort_values("triage_risk", ascending=False).head(args.topk)
        version_risk = float(topk["triage_risk"].mean()) if len(topk) else 0.0

        lib_count = int(len(dv))
        dq = "ok" if lib_count >= MIN_LIBS_FOR_VERSION else "partial"

        per_version[v] = dv[["library", "raw_risk"] + HL_METRICS].copy()
        summary[v] = {"vr": version_risk, "libs": lib_count, "dq": dq}

    rows_out: List[str] = []
    prev_v = None

    header = (
        "iOS_VERSION   VERSION_RISK  DATA_QUALITY  RELEASE_LABEL"
        "COMMON  OVERLAP  ΔRAW%   ΔSYMS%  ΔIMPS%  ΔSECS%  LIBS"
    )

    for v in versions:
        vr = summary[v]["vr"]
        dq = summary[v]["dq"]
        libs = summary[v]["libs"]

        if prev_v is None:
            rows_out.append(
                f"{v:<12} {vr:>12.6f}  {dq:<12}  {'n/a':<20} {'-':>6}  {'-':>7}  {'-':>6}  {'-':>6}  {'-':>6}  {'-':>6}  {libs:>4}"
            )
            prev_v = v
            continue

        prev_dq = summary[prev_v]["dq"]
        if prev_dq != "ok" or dq != "ok":
            rows_out.append(
                f"{v:<12} {vr:>12.6f}  {dq:<12}  {'partial_snapshot':<20} {'-':>6}  {'-':>7}  {'-':>6}  {'-':>6}  {'-':>6}  {'-':>6}  {libs:>4}"
            )
            prev_v = v
            continue

        a = per_version[prev_v]
        b = per_version[v]
        common = a.merge(b, on="library", how="inner", suffixes=("_prev", "_cur"))
        common_libs = int(len(common))
        overlap = common_libs / max(len(a), len(b)) if max(len(a), len(b)) else 0.0

        if common_libs < MIN_COMMON or overlap < MIN_OVERLAP:
            rows_out.append(
                f"{v:<12} {vr:>12.6f}  {dq:<12}  {'insufficient_overlap':<20} {common_libs:>6}  {overlap:>7.3f}  {'-':>6}  {'-':>6}  {'-':>6}  {'-':>6}  {libs:>4}"
            )
            prev_v = v
            continue

        d_raw = pct_change(float(common["raw_risk_prev"].mean()), float(common["raw_risk_cur"].mean()))
        d_syms = pct_change(float(common["num_symbols_prev"].mean()), float(common["num_symbols_cur"].mean()))
        d_imps = pct_change(float(common["import_count_prev"].mean()), float(common["import_count_cur"].mean()))
        d_secs = pct_change(float(common["num_sections_prev"].mean()), float(common["num_sections_cur"].mean()))

        lab = classify(d_raw, d_syms, d_imps, d_secs)

        rows_out.append(
            f"{v:<12} {vr:>12.6f}  {dq:<12}  {lab:<20} {common_libs:>6}  {overlap:>7.3f}  {d_raw*100:>6.2f}  {d_syms*100:>6.2f}  {d_imps*100:>6.2f}  {d_secs*100:>6.2f}  {libs:>4}"
        )

        prev_v = v

    print(header)
    print("-" * len(header))
    for line in rows_out:
        print(line)


if __name__ == "__main__":
    main()
