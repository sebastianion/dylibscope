if currentProgram is None:
    exit(0)
    

try: setAnalysisOption(currentProgram, "Decompiler Parameter ID", "false")
except: pass
try: setAnalysisOption(currentProgram, "Decompiler Calling Convention", "false")
except: pass
try: setAnalysisOption(currentProgram, "Decompiler Switch Analysis", "false")
except: pass

