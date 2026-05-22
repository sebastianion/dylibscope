from dylibscope.security_analysis.hla_trend_analysis import run_hla_trend_analysis
from dylibscope.security_analysis.lla_trend_analysis import run_lla_trend_analysis


def main() -> None:
    print("=" * 16, "High-level security trend analysis", "=" * 16)
    run_hla_trend_analysis()

    print("\n")

    print("=" * 16, "Low-level security trend analysis", "=" * 16)
    run_lla_trend_analysis()


if __name__ == "__main__":
    main()