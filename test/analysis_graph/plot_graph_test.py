from __future__ import annotations

import json

from dylibscope.analysis_graph.models import AnalysisConfig
from dylibscope.analysis_graph.plot_graph import Graph
from dylibscope.config.ios_versions import IOS_VERSION


def write_jsonl(path, rows):
    path.write_text(
        "\n".join(json.dumps(row) for row in rows) + "\n",
        encoding="utf-8",
    )


def build_test_config(preprocess=None):
    return AnalysisConfig(
        metrics={
            "metric_a": "Metric A",
            "metric_b": "Metric B",
        },
        library_label="library",
        default_metric_label="metric_a",
        title="Test Graph",
        preprocess=preprocess,
    )


def test_graph_loads_and_normalizes_dataframe(tmp_path):
    input_file = tmp_path / "input.jsonl"

    write_jsonl(
        input_file,
        [
            {
                "library": "libA.dylib",
                "ios_version": "iPhone5,1_8.0_12A365",
                "metric_a": 10,
                "metric_b": 100,
            },
            {
                "library": "libA.dylib",
                "ios_version": "iPhone5,1_9.0_13A344",
                "metric_a": 20,
                "metric_b": 200,
            },
        ],
    )

    graph = Graph(input_file, build_test_config())

    assert list(graph.df[IOS_VERSION].astype(str)) == ["iOS 8.0", "iOS 9.0"]
    assert list(graph.libs) == ["libA.dylib"]
    assert graph.metrics == {"metric_a": "Metric A", "metric_b": "Metric B"}


def test_graph_applies_preprocess_function(tmp_path):
    input_file = tmp_path / "input.jsonl"

    write_jsonl(
        input_file,
        [
            {
                "library": "libA.dylib",
                "ios_version": "iPhone5,1_8.0_12A365",
                "base_metric": 10,
            }
        ],
    )

    def preprocess(df):
        df = df.copy()
        df["metric_a"] = df["base_metric"] * 2
        df["metric_b"] = df["base_metric"] * 3
        return df

    graph = Graph(input_file, build_test_config(preprocess=preprocess))

    assert graph.df.loc[0, "metric_a"] == 20
    assert graph.df.loc[0, "metric_b"] == 30


def test_build_figure_adds_one_trace_per_metric_and_library(tmp_path):
    input_file = tmp_path / "input.jsonl"

    write_jsonl(
        input_file,
        [
            {
                "library": "libA.dylib",
                "ios_version": "iPhone5,1_8.0_12A365",
                "metric_a": 10,
                "metric_b": 100,
            },
            {
                "library": "libB.dylib",
                "ios_version": "iPhone5,1_8.0_12A365",
                "metric_a": 20,
                "metric_b": 200,
            },
        ],
    )

    graph = Graph(input_file, build_test_config())
    graph.sort_df_by_label()
    graph.build_figure()

    assert len(graph.fig.data) == 4

    metric_a_traces = graph.fig.data[:2]
    metric_b_traces = graph.fig.data[2:]

    assert all(trace.visible for trace in metric_a_traces)
    assert all(not trace.visible for trace in metric_b_traces)


def test_handle_convergence_points_adds_overlay_trace(tmp_path):
    input_file = tmp_path / "input.jsonl"

    write_jsonl(
        input_file,
        [
            {
                "library": "libA.dylib",
                "ios_version": "iPhone5,1_8.0_12A365",
                "metric_a": 10,
                "metric_b": 100,
            },
            {
                "library": "libB.dylib",
                "ios_version": "iPhone5,1_8.0_12A365",
                "metric_a": 10,
                "metric_b": 200,
            },
        ],
    )

    graph = Graph(input_file, build_test_config())
    graph.sort_df_by_label()
    graph.build_figure()
    graph.handle_convergence_points()

    assert len(graph.overlay_indices) == 2

    first_overlay = graph.fig.data[graph.overlay_indices[0]]

    assert first_overlay.name == "Converging libraries (Metric A)"
    assert len(first_overlay.x) == 1
    assert len(first_overlay.y) == 1


def test_create_dropdown_buttons_creates_one_button_per_metric(tmp_path):
    input_file = tmp_path / "input.jsonl"

    write_jsonl(
        input_file,
        [
            {
                "library": "libA.dylib",
                "ios_version": "iPhone5,1_8.0_12A365",
                "metric_a": 10,
                "metric_b": 100,
            },
            {
                "library": "libB.dylib",
                "ios_version": "iPhone5,1_8.0_12A365",
                "metric_a": 20,
                "metric_b": 200,
            },
        ],
    )

    graph = Graph(input_file, build_test_config())
    graph.sort_df_by_label()
    graph.build_figure()
    graph.handle_convergence_points()
    graph.create_dropdown_buttons()

    assert len(graph.buttons) == 2
    assert graph.buttons[0]["label"] == "Metric A"
    assert graph.buttons[1]["label"] == "Metric B"


def test_render_writes_html_file(tmp_path):
    input_file = tmp_path / "input.jsonl"
    output_file = tmp_path / "plots" / "graph.html"

    write_jsonl(
        input_file,
        [
            {
                "library": "libA.dylib",
                "ios_version": "iPhone5,1_8.0_12A365",
                "metric_a": 10,
                "metric_b": 100,
            },
            {
                "library": "libB.dylib",
                "ios_version": "iPhone5,1_9.0_13A344",
                "metric_a": 20,
                "metric_b": 200,
            },
        ],
    )

    graph = Graph(input_file, build_test_config())
    graph.render(output_file)

    assert output_file.exists()
    assert "plotly" in output_file.read_text(encoding="utf-8").lower()