from pandas import DataFrame
from analysis_graph.models import AnalysisConfig, SecurityProfile

def hla_preprocess(df: DataFrame):
    df["num_exported_functions"] = df["exported_functions"].apply(lambda x: len(x.split(";")) if x else 0)
    df["num_imported_functions"] = df["imported_functions"].apply(lambda x: len(x.split(";")) if x else 0)
    return df

HLA_METRICS = {
    "num_sections": "Number of sections",
    "num_symbols": "Number of symbols",
    "num_exported_functions": "Number of exported functions",
    "num_imported_functions": "Number of imported functions"
}

DEFAULT_HLA_METRIC_KEY = "num_symbols" 
HLA_LIBRARY_LABEL = "file"
HLA_TITLE = "Evolution of libraries across iOS versions: High level analysis"

HLA_INPUT_FILE_PATH = "high_level_analysis/dylibs_analysis_local.json"
HLA_OUTPUT_FILE_NAME = "output_analysis_graph/high_level_analysis_dylib_evolution.html"

HLA_WEIGHTS = {
    "num_exported_functions": 1.0,
    "num_imported_functions": 0.8,
    "num_symbols": 0.5,
    "num_sections": 0.3,
}

HLA_SECURITY_LENS = {
    "num_exported_functions": "Exports ↑ ⇒ broader public API surface (more entry points / hookable interfaces).",
    "num_imported_functions": "Imports ↑ ⇒ dependency footprint expands (more transitive risk and ABI surface).",
    "num_symbols": "Symbols ↑ ⇒ greater RE visibility unless stripped; can correlate with feature growth.",
    "num_sections": "Sections ↑ ⇒ structural complexity increases; can indicate added components/features.",
}

HLA = AnalysisConfig(
    metrics=HLA_METRICS,
    default_metric_label=DEFAULT_HLA_METRIC_KEY,
    library_label=HLA_LIBRARY_LABEL,
    title=HLA_TITLE,
    preprocess=hla_preprocess
)

HLA_SECURITY = SecurityProfile(
    name = "hla",
    weights = HLA_WEIGHTS,
    security_lens = HLA_SECURITY_LENS
)