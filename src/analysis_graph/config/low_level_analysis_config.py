from analysis_graph.models import AnalysisConfig, SecurityProfile

LLA_METRICS = {
    "cfg_edge_count": "Complexity of control flow graph (number of edges)",
    "internal_function_count": "Number of internal functions",
    "internal_variable_count": "Number of internal variables",
    "mach_port_function_count": "Number of functions containing mach-port calls",
    "syscall_function_count": "Number of syscalls",
    "allocation_call_count": "Number of allocation calls"
}

DEFAULT_LLA_METRIC_KEY = "cfg_edge_count" 
LLA_LIBRARY_LABEL = "library"
LLA_TITLE = "Evolution of libraries across iOS versions: Low level analysis"

LLA_INPUT_FILE_PATH = "low_level_analysis/ghidra_out/merged.json"
LLA_OUTPUT_FILE_NAME = "output_analysis_graph/low_level_analysis_dylib_evolution.html"

LLA_WEIGHTS = {
    "mach_port_function_count": 1.0,
    "syscall_function_count": 0.9,
    "cfg_edge_count": 0.6,
    "internal_function_count": 0.4,
    "internal_variable_count": 0.3,
    "allocation_call_count": 0.2
}

LLA_SECURITY_LENS = {
    "mach_port_function_count": "Mach port usage ↑ ⇒ more IPC/privileged interaction surfaces (audit carefully).",
    "syscall_function_count": "Syscalls ↑ ⇒ more kernel interaction; review for risky primitives and input validation.",
    "cfg_edge_count": "CFG complexity ↑ ⇒ harder auditing & larger bug surface; may raise exploitability risk.",
    "internal_function_count": "Internal functions ↑ ⇒ feature growth; may expand hidden attack surface too.",
    "internal_variable_count": "Variables ↑ ⇒ statefulness/complexity; can correlate with bug density.",
    "allocation_call_count": "Allocations ↑ ⇒ more heap activity; watch for memory safety patterns.",
}

LLA = AnalysisConfig(
    metrics=LLA_METRICS,
    default_metric_label=DEFAULT_LLA_METRIC_KEY,
    library_label=LLA_LIBRARY_LABEL,
    title=LLA_TITLE
)

LLA_SECURITY = SecurityProfile(
    name = "lla",
    weights = LLA_WEIGHTS,
    security_lens = LLA_SECURITY_LENS
)