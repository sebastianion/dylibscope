from dylibscope.analysis_graph.config.low_level_analysis_config import LLA, LLA_INPUT_FILE_PATH, LLA_OUTPUT_FILE_NAME
from dylibscope.analysis_graph.plot_graph import Graph

if __name__ == "__main__":
    Graph(LLA_INPUT_FILE_PATH, LLA).render(LLA_OUTPUT_FILE_NAME)
