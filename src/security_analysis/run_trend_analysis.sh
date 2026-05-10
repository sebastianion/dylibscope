#!/bin/bash
set -euo pipefail

echo
echo "================ HIGH-LEVEL ANALYSIS (HLA) ================"
echo
python3 -m security_analysis.hla_trend_analysis \
  --in "high_level_analysis/dylibs_analysis_local.json"

echo
echo "================ LOW-LEVEL ANALYSIS (LLA) ================"
echo
python3 -m security_analysis.lla_trend_analysis \
  --in "low_level_analysis/ghidra_out/merged.json"
