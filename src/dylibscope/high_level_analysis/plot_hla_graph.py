from dylibscope.analysis_graph.config.high_level_analysis_config import HLA, HLA_OUTPUT_FILE_NAME
from dylibscope.analysis_graph.plot_graph import Graph
from dylibscope.config.datasets import HLA_INPUT

if __name__ == "__main__":
    Graph(HLA_INPUT, HLA).render(HLA_OUTPUT_FILE_NAME)
