from __future__ import annotations
import pandas as pd
from pandas import DataFrame
import plotly.graph_objects as go
import json
from pathlib import Path

from dylibscope.config.ios_versions import VERSION_ORDER, IOS_VERSION
from dylibscope.analysis_graph.models import AnalysisConfig
from dylibscope.config.versioning import normalize_ios_versions
from dylibscope.config.io import load_jsonl


class Graph:

    def __init__(self, data_file: str, config: AnalysisConfig):
        self.fig = go.Figure()
        self.preprocess = config.preprocess
        self.df = self.__create_data_frame(data_file)
        self.library_label = config.library_label
        self.libs = self.df[self.library_label].unique()
        self.metrics = config.metrics
        self.default_metric_label = config.default_metric_label
        self.title = config.title
        self.overlay_indices = []
        self.buttons = []


    def __create_data_frame(self, data_file: str):
        df = load_jsonl(data_file)
        if self.preprocess:
            df = self.preprocess(df)

        return normalize_ios_versions(df)
    

    def sort_df_by_label(self):
        self.df = self.df.sort_values([self.library_label, IOS_VERSION])


    def build_figure(self):
        for metric_key in self.metrics.keys():
            for lib, group in self.df.groupby(self.library_label, sort=False):
                g = group.sort_values(IOS_VERSION)
                self.fig.add_trace(go.Scatter(
                    x=g[IOS_VERSION],
                    y=g[metric_key],
                    mode="lines+markers",
                    name=lib,
                    visible=(metric_key == self.default_metric_label)
                ))
        
        self.fig.update_traces(
            hovertemplate="<b>%{fullData.name}</b><br>Value: %{y}<extra></extra>"
        )


    def handle_convergence_points(self):
        for metric_key, label in self.metrics.items():
            tmp = self.df[[self.library_label, IOS_VERSION, metric_key]].dropna().copy()
            tmp.rename(columns={metric_key: "value"}, inplace=True)

            dup = (
                tmp.groupby([IOS_VERSION, "value"])[self.library_label]
                .agg(list)
                .reset_index()
            )
            dup = dup[dup[self.library_label].str.len() >= 2]

            self.overlay_indices.append(len(self.fig.data))
            if dup.empty:
                self.fig.add_trace(go.Scatter(
                    x=[], y=[],
                    mode="markers",
                    name=f"Converging libraries ({label})",
                    marker=dict(size=10, symbol="x-thin"),
                    hovertemplate="<extra></extra>",
                    visible=(metric_key == self.default_metric_label)
                ))
                continue

            hover_text = [
                "<br>".join(f"<b>{lib}</b>" for lib in libs_list) + f"<br>Value: {val}"
                for libs_list, val in zip(dup[self.library_label], dup["value"])
            ]

            self.fig.add_trace(go.Scatter(
                x=dup[IOS_VERSION],
                y=dup["value"],
                mode="markers",
                name=f"Converging libraries ({label})",
                marker=dict(size=10, symbol="diamond-open"),
                hovertemplate="%{text}<extra></extra>",
                text=hover_text,
                visible=(metric_key == self.default_metric_label)
            ))
    

    def create_dropdown_buttons(self):
        n_libs = len(self.libs)
        for i, (metric_key, label) in enumerate(self.metrics.items()):
            visible = [False] * len(self.fig.data)

            start = i * n_libs
            for j in range(n_libs):
                visible[start + j] = True

            visible[self.overlay_indices[i]] = True

            self.buttons.append(dict(
                label=label,
                method="update",
                args=[
                    {"visible": visible},
                    {
                        "title.text": self.title,
                        "title.x": 0.5,
                        "title.xanchor": "center",
                        "title.font.size": 24,
                        "yaxis.title.text": label,
                    },
                ],
            ))


    def update_layout(self):
        menu = dict(
            buttons=self.buttons,
            direction="down",
            x=0, xanchor="left",
            y=1.15, yanchor="top",
            pad={"r": 8, "t": 8},
            bgcolor="white",
            bordercolor="lightgray",
            showactive=True
        )

        self.fig.update_layout(
            updatemenus=[menu],
            margin=dict(t=120),
            xaxis_title="iOS Version",
            title=dict(text=self.title, x=0.5, xanchor="center", font=dict(size=24)),
            hovermode="closest"
        )

        self.fig.update_xaxes(
            type="category",
            categoryorder="array",
            categoryarray=VERSION_ORDER
        )
    

    def save_to_file(self, output_file_name: str | Path):
        output_file = Path(output_file_name)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        self.fig.write_html(str(output_file), include_plotlyjs="cdn", full_html=True)


    def render(self, output_file_name: str | Path) -> None:
        self.sort_df_by_label()
        self.build_figure()
        self.handle_convergence_points()
        self.create_dropdown_buttons()
        self.update_layout()
        self.save_to_file(output_file_name)