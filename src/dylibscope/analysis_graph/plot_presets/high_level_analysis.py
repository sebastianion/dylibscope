from pandas import DataFrame

from dylibscope.analysis_graph.models import AnalysisConfig
from dylibscope.config.paths import DOCS_DIR


def hla_preprocess(df: DataFrame):
    df["num_exported_functions"] = df["exported_functions"].apply(lambda x: len(x.split(";")) if x else 0)
    df["num_imported_functions"] = df["imported_functions"].apply(lambda x: len(x.split(";")) if x else 0)
    return df


HLA_METRICS = {
    "num_sections": "Number of sections",
    "num_symbols": "Number of symbols",
    "num_exported_functions": "Number of exported functions",
    "num_imported_functions": "Number of imported functions",
}

DEFAULT_HLA_METRIC_KEY = "num_symbols"
HLA_LIBRARY_LABEL = "file"
HLA_TITLE = "Evolution of libraries across iOS versions: High level analysis"

HLA_PLOT_OUTPUT = DOCS_DIR / "high_level_analysis_dylib_evolution.html"

HLA = AnalysisConfig(
    metrics=HLA_METRICS,
    default_metric_label=DEFAULT_HLA_METRIC_KEY,
    library_label=HLA_LIBRARY_LABEL,
    title=HLA_TITLE,
    preprocess=hla_preprocess,
)
