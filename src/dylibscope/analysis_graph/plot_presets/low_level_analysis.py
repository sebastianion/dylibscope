from dylibscope.analysis_graph.models import AnalysisConfig
from dylibscope.config.paths import DOCS_DIR

LLA_METRICS = {
    "cfg_edge_count": "Complexity of control flow graph (number of edges)",
    "internal_function_count": "Number of internal functions",
    "internal_variable_count": "Number of internal variables",
    "mach_port_function_count": "Number of functions containing mach-port calls",
    "syscall_function_count": "Number of syscalls",
    "allocation_call_count": "Number of allocation calls",
}

DEFAULT_LLA_METRIC_KEY = "cfg_edge_count"
LLA_LIBRARY_LABEL = "library"
LLA_TITLE = "Evolution of libraries across iOS versions: Low level analysis"

LLA_PLOT_OUTPUT = DOCS_DIR / "low_level_analysis_dylib_evolution.html"

LLA = AnalysisConfig(
    metrics=LLA_METRICS, default_metric_label=DEFAULT_LLA_METRIC_KEY, library_label=LLA_LIBRARY_LABEL, title=LLA_TITLE
)
