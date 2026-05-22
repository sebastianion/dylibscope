from dylibscope.analysis_graph.config.high_level_analysis_config import HLA, HLA_INPUT_FILE_PATH, HLA_OUTPUT_FILE_NAME
from dylibscope.analysis_graph.config.low_level_analysis_config import LLA, LLA_INPUT_FILE_PATH, LLA_OUTPUT_FILE_NAME
from dylibscope.analysis_graph.plot_graph import Graph


def main() -> None:
    Graph(HLA_INPUT_FILE_PATH, HLA).render(HLA_OUTPUT_FILE_NAME)
    Graph(LLA_INPUT_FILE_PATH, LLA).render(LLA_OUTPUT_FILE_NAME)

    print(f"Generated high-level plot: {HLA_OUTPUT_FILE_NAME}")
    print(f"Generated low-level plot: {LLA_OUTPUT_FILE_NAME}")


if __name__ == "__main__":
    main()
