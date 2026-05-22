# ruff: noqa: F821
if currentProgram is None:
    exit(0)


try:
    setAnalysisOption(currentProgram, "Decompiler Parameter ID", "false")
except Exception:
    pass

try:
    setAnalysisOption(currentProgram, "Decompiler Calling Convention", "false")
except Exception:
    pass

try:
    setAnalysisOption(currentProgram, "Decompiler Switch Analysis", "false")
except Exception:
    pass
