from analysis_graph.config.high_level_analysis_config import HLA, HLA_INPUT_FILE_PATH, HLA_OUTPUT_FILE_NAME
from analysis_graph.plot_graph import Graph

if __name__ == "__main__":
    Graph(HLA_INPUT_FILE_PATH, HLA).render(HLA_OUTPUT_FILE_NAME)
