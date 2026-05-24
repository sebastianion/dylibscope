import argparse
from pathlib import Path

from dylibscope.analysis_graph.plot_graph import Graph
from dylibscope.analysis_graph.plot_presets.high_level_analysis import HLA, HLA_PLOT_OUTPUT
from dylibscope.analysis_graph.plot_presets.low_level_analysis import LLA, LLA_PLOT_OUTPUT
from dylibscope.config.datasets import HLA_INPUT, LLA_INPUT


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate DylibScope interactive Plotly graphs.")
    parser.add_argument(
        "--hla-input",
        type=Path,
        default=HLA_INPUT,
        help="Path to the high-level JSONL dataset.",
    )
    parser.add_argument(
        "--lla-input",
        type=Path,
        default=LLA_INPUT,
        help="Path to the low-level JSONL dataset.",
    )
    parser.add_argument(
        "--hla-output",
        type=Path,
        default=HLA_PLOT_OUTPUT,
        help="Output path for the high-level HTML plot.",
    )
    parser.add_argument(
        "--lla-output",
        type=Path,
        default=LLA_PLOT_OUTPUT,
        help="Output path for the low-level HTML plot.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    Graph(args.hla_input, HLA).render(args.hla_output)
    Graph(args.lla_input, LLA).render(args.lla_output)

    print(f"Generated high-level plot: {args.hla_output}")
    print(f"Generated low-level plot: {args.lla_output}")


if __name__ == "__main__":
    main()
