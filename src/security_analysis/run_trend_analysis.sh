#!/bin/bash
set -euo pipefail

echo
echo "================ HIGH-LEVEL ANALYSIS (HLA) ================"
echo
PYTHONPATH=src python3 src/security_analysis/hla_trend_analysis.py --in src/high_level_analysis/dylibs_analysis_local.json

echo
echo "================ LOW-LEVEL ANALYSIS (LLA) ================"
echo
PYTHONPATH=src python3 src/security_analysis/lla_trend_analysis.py --in src/low_level_analysis/ghidra_out/merged.json
