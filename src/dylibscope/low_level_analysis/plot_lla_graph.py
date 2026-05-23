from dylibscope.analysis_graph.config.low_level_analysis_config import LLA, LLA_OUTPUT_FILE_NAME
from dylibscope.analysis_graph.plot_graph import Graph
from dylibscope.config.datasets import LLA_INPUT

if __name__ == "__main__":
    Graph(LLA_INPUT, LLA).render(LLA_OUTPUT_FILE_NAME)
