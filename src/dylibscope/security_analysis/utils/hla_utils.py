HL_METRICS = ["num_symbols", "import_count", "num_sections"]

W_RAW = {
    "num_symbols": 0.55,
    "import_count": 0.30,
    "num_sections": 0.15,
}

W_TRIAGE = W_RAW.copy()

MIN_LIBS_FOR_VERSION = 150
MIN_COMMON = 150
MIN_OVERLAP = 0.60

THR_RAW_RISK = 0.01
THR_SYMS = 0.07
THR_IMPS = 0.07
THR_SECS = 0.07
