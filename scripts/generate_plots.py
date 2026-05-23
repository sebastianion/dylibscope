from dylibscope.analysis_graph.plot_presets.high_level_analysis import HLA, HLA_PLOT_OUTPUT
from dylibscope.analysis_graph.plot_presets.low_level_analysis import LLA, LLA_PLOT_OUTPUT
from dylibscope.analysis_graph.plot_graph import Graph
from dylibscope.config.datasets import HLA_INPUT, LLA_INPUT


def main() -> None:
    Graph(HLA_INPUT, HLA).render(HLA_PLOT_OUTPUT)
    Graph(LLA_INPUT, LLA).render(LLA_PLOT_OUTPUT)

    print(f"Generated high-level plot: {HLA_PLOT_OUTPUT}")
    print(f"Generated low-level plot: {LLA_PLOT_OUTPUT}")


if __name__ == "__main__":
    main()
