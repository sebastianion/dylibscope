RISK_METRICS = ["cfg_edge_count", "allocation_call_count", "mach_port_function_count", "syscall_function_count"]
ALL_METRICS = RISK_METRICS + ["internal_function_count", "internal_variable_count"]

WEIGHTS = {
    "cfg_edge_count": 0.50,
    "allocation_call_count": 0.25,
    "mach_port_function_count": 0.15,
    "syscall_function_count": 0.10,
}

MIN_LIBS_FOR_VERSION = 150
MIN_COMMON = 150
MIN_OVERLAP = 0.60

THR_RAW_RISK = 0.03
THR_CFG = 0.05
THR_ALLOC = 0.05
THR_BOUNDARY = 0.05
