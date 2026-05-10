from __future__ import annotations

import argparse
import math
from typing import Dict, List

import pandas as pd


from config.ios_versions import VERSION_ORDER
from config.io import load_jsonl
from config.versioning import normalize_version_label

from security_analysis.utils.common_utils import (
    pick_col,
    lib_base,
    to_int,
    norm01,
    pct_change,
)

from security_analysis.utils.lla_utils import *


def raw_risk_lib(cfg: float, alloc: float, mach: float, syscall: float) -> float:
    return (
        WEIGHTS["cfg_edge_count"] * math.log1p(max(cfg, 0.0))
        + WEIGHTS["allocation_call_count"] * math.log1p(max(alloc, 0.0))
        + WEIGHTS["mach_port_function_count"] * math.log1p(max(mach, 0.0))
        + WEIGHTS["syscall_function_count"] * math.log1p(max(syscall, 0.0))
    )


def classify(delta_raw_risk: float, delta_cfg: float, delta_alloc: float, delta_boundary: float) -> str:
    hardening = (delta_raw_risk <= -THR_RAW_RISK) and (
        delta_boundary <= -THR_BOUNDARY or delta_alloc <= -THR_ALLOC or delta_cfg <= -THR_CFG
    )
    expanding = (delta_raw_risk >= +THR_RAW_RISK) and (
        delta_boundary >= +THR_BOUNDARY or delta_alloc >= +THR_ALLOC or delta_cfg >= +THR_CFG
    )
    if hardening:
        return "hardening"
    if expanding:
        return "expanding"
    return "stable"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="in_path", default="/mnt/data/merged.json")
    ap.add_argument("--topk", type=int, default=20)
    args = ap.parse_args()

    df = load_jsonl(args.in_path)
    vcol = pick_col(df, ["ios_version", "version", "ios", "os_version"])
    lcol = pick_col(df, ["library", "lib", "name", "image_name", "path"])

    df = df.rename(columns={vcol: "ios_version", lcol: "library"})
    df["ios_version"] = df["ios_version"].map(normalize_version_label)
    df["library"] = df["library"].map(lib_base)

    for m in ALL_METRICS:
        if m not in df.columns:
            df[m] = 0
        df[m] = df[m].map(to_int)

    df = df.groupby(["ios_version", "library"], as_index=False).agg({m: "max" for m in ALL_METRICS})

    present_versions = set(df["ios_version"].unique())
    versions = [v for v in VERSION_ORDER if v in present_versions]

    per_version: Dict[str, pd.DataFrame] = {}
    summary: Dict[str, Dict[str, float]] = {}

    for v in versions:
        dv = df[df["ios_version"] == v].copy()

        for m in RISK_METRICS:
            dv[m + "_n"] = norm01(dv[m])

        dv["triage_risk"] = 0.0
        for m, w in WEIGHTS.items():
            dv["triage_risk"] += w * dv[m + "_n"]

        dv["boundary"] = dv["mach_port_function_count"] + dv["syscall_function_count"]

        dv["raw_risk"] = dv.apply(
            lambda r: raw_risk_lib(
                r["cfg_edge_count"],
                r["allocation_call_count"],
                r["mach_port_function_count"],
                r["syscall_function_count"],
            ),
            axis=1,
        )

        topk = dv.sort_values("triage_risk", ascending=False).head(args.topk)
        version_risk = float(topk["triage_risk"].mean()) if len(topk) else 0.0

        lib_count = int(len(dv))
        dq = "ok" if lib_count >= MIN_LIBS_FOR_VERSION else "partial"

        per_version[v] = dv[["library", "raw_risk"] + ALL_METRICS].copy()
        summary[v] = {
            "version_risk": version_risk,
            "libs": lib_count,
            "dq": dq,
            "boundary_total": int(dv["boundary"].sum()),
        }

    rows_out: List[str] = []
    prev_v = None

    header = (
        "iOS_VERSION   VERSION_RISK  DATA_QUALITY  RELEASE_LABEL        "
        "COMMON  OVERLAP  ΔRAW%   ΔCFG%   ΔALLOC%  ΔBOUND%  LIBS  BOUNDARY"
    )

    for v in versions:
        vr = summary[v]["version_risk"]
        dq = summary[v]["dq"]
        libs = summary[v]["libs"]
        btot = summary[v]["boundary_total"]

        if prev_v is None:
            rows_out.append(
                f"{v:<12} {vr:>12.6f}  {dq:<12}  {'n/a':<20} {'-':>6}  {'-':>7}  {'-':>6}  {'-':>6}  {'-':>7}  {'-':>7}  {libs:>5}  {btot:>8}"
            )
            prev_v = v
            continue

        prev_dq = summary[prev_v]["dq"]
        if prev_dq != "ok" or dq != "ok":
            rows_out.append(
                f"{v:<12} {vr:>12.6f}  {dq:<12}  {'partial_snapshot':<20} {'-':>6}  {'-':>7}  {'-':>6}  {'-':>6}  {'-':>7}  {'-':>7}  {libs:>5}  {btot:>8}"
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
                f"{v:<12} {vr:>12.6f}  {dq:<12}  {'insufficient_overlap':<20} {common_libs:>6}  {overlap:>7.3f}  {'-':>6}  {'-':>6}  {'-':>7}  {'-':>7}  {libs:>5}  {btot:>8}"
            )
            prev_v = v
            continue

        d_raw = pct_change(float(common["raw_risk_prev"].mean()), float(common["raw_risk_cur"].mean()))
        d_cfg = pct_change(float(common["cfg_edge_count_prev"].mean()), float(common["cfg_edge_count_cur"].mean()))
        d_alloc = pct_change(float(common["allocation_call_count_prev"].mean()), float(common["allocation_call_count_cur"].mean()))
        prev_boundary = float((common["mach_port_function_count_prev"] + common["syscall_function_count_prev"]).mean())
        cur_boundary = float((common["mach_port_function_count_cur"] + common["syscall_function_count_cur"]).mean())
        d_bound = pct_change(prev_boundary, cur_boundary)

        lab = classify(d_raw, d_cfg, d_alloc, d_bound)

        rows_out.append(
            f"{v:<12} {vr:>12.6f}  {dq:<12}  {lab:<20} {common_libs:>6}  {overlap:>7.3f}  {d_raw*100:>6.2f}  {d_cfg*100:>6.2f}  {d_alloc*100:>7.2f}  {d_bound*100:>7.2f}  {libs:>5}  {btot:>8}"
        )

        prev_v = v

    print(header)
    print("-" * len(header))
    for line in rows_out:
        print(line)


if __name__ == "__main__":
    main()
