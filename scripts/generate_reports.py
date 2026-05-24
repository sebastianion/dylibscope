import argparse
from pathlib import Path

from dylibscope.security_analysis.hla_trend_analysis import run_hla_trend_analysis
from dylibscope.security_analysis.lla_trend_analysis import run_lla_trend_analysis
from dylibscope.config.datasets import HLA_INPUT, LLA_INPUT


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate DylibScope security trend reports."
    )
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
    return parser.parse_args()



def main() -> None:
    args = parse_args()

    print("=" * 16, "High-level security trend analysis", "=" * 16)
    run_hla_trend_analysis(input_path=args.hla_input)

    print("\n")

    print("=" * 16, "Low-level security trend analysis", "=" * 16)
    run_lla_trend_analysis(input_path=args.lla_input)


if __name__ == "__main__":
    main()
