"""
ui/charts.py

Plotly vizualizasiyaları:
- Posture score gauge
- Severity donut chart
- Category bar chart
- Score trend line chart
"""

import plotly.graph_objects as go
import pandas as pd


def get_gauge_chart(score: int) -> go.Figure:
    """Posture Score üçün dəqiq və müasir gauge qrafiki."""
    if score >= 80:
        bar_color = "#10b981"  # Yaşıl
    elif score >= 50:
        bar_color = "#f59e0b"  # Sarı
    else:
        bar_color = "#ef4444"  # Qırmızı

    fig = go.Figure(
        go.Indicator(
            mode="gauge+number",
            value=score,
            number={"suffix": "/100", "font": {"size": 36, "color": "#e8eaed"}},
            title={"text": "Azure Posture Score", "font": {"size": 18, "color": "#94a3b8"}},
            gauge={
                "axis": {"range": [0, 100], "tickwidth": 1, "tickcolor": "#475569"},
                "bar": {"color": bar_color, "thickness": 0.28},
                "bgcolor": "rgba(21, 26, 33, 0.8)",
                "borderwidth": 1,
                "bordercolor": "#334155",
                "steps": [
                    {"range": [0, 50], "color": "rgba(239, 68, 68, 0.15)"},
                    {"range": [50, 80], "color": "rgba(245, 158, 11, 0.15)"},
                    {"range": [80, 100], "color": "rgba(16, 185, 129, 0.15)"},
                ],
                "threshold": {
                    "line": {"color": "#2dd4bf", "width": 3},
                    "thickness": 0.75,
                    "value": score,
                },
            },
        )
    )
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        margin=dict(l=25, r=25, t=50, b=25),
        height=240,
    )
    return fig


def get_severity_donut(counts: dict) -> go.Figure:
    """Təhlükə dərəcələrinə (High/Med/Low) görə donut qrafiki."""
    labels = ["High", "Medium", "Low"]
    values = [counts.get("High", 0), counts.get("Medium", 0), counts.get("Low", 0)]
    colors = ["#ef4444", "#f59e0b", "#10b981"]

    total = sum(values)
    if total == 0:
        # Boş hal
        fig = go.Figure(
            go.Pie(
                labels=["Təmiz"],
                values=[1],
                hole=0.65,
                marker=dict(colors=["#10b981"]),
                textinfo="label",
            )
        )
    else:
        fig = go.Figure(
            go.Pie(
                labels=labels,
                values=values,
                hole=0.65,
                marker=dict(colors=colors, line=dict(color="#151a21", width=2)),
                hoverinfo="label+value+percent",
                textinfo="value",
                textfont=dict(size=14, color="#ffffff", family="sans-serif"),
            )
        )

    fig.update_layout(
        showlegend=True,
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=-0.2,
            xanchor="center",
            x=0.5,
            font=dict(color="#94a3b8"),
        ),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        margin=dict(l=10, r=10, t=10, b=30),
        height=240,
    )
    return fig


def get_category_bar(findings: list[dict]) -> go.Figure:
    """Resurs kateqoriyalarına görə tapıntıların paylanması."""
    if not findings:
        return go.Figure()

    df = pd.DataFrame(findings)
    cat_counts = df["category"].value_counts().reset_index()
    cat_counts.columns = ["category", "count"]

    fig = go.Figure(
        go.Bar(
            x=cat_counts["count"],
            y=cat_counts["category"],
            orientation="h",
            marker=dict(
                color="#2dd4bf",
                line=dict(color="#14b8a6", width=1),
            ),
            text=cat_counts["count"],
            textposition="auto",
        )
    )
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        xaxis=dict(showgrid=True, gridcolor="#272f3d", zeroline=False, color="#94a3b8"),
        yaxis=dict(color="#e8eaed", autorange="reversed"),
        margin=dict(l=10, r=10, t=10, b=10),
        height=220,
    )
    return fig


def get_trend_chart(history: list[dict]) -> go.Figure:
    """Bütün skanlar üzrə posture score trend xətti."""
    if len(history) < 2:
        return go.Figure()

    df = pd.DataFrame(history)
    df["display_time"] = pd.to_datetime(df["time"]).dt.strftime("%b %d, %H:%M")

    fig = go.Figure()
    fig.add_trace(
        go.Scatter(
            x=df["display_time"],
            y=df["score"],
            mode="lines+markers",
            line=dict(color="#2dd4bf", width=3, shape="spline"),
            marker=dict(size=8, color="#2dd4bf", line=dict(color="#ffffff", width=1.5)),
            fill="tozeroy",
            fillcolor="rgba(45, 212, 191, 0.08)",
            hovertemplate="<b>%{x}</b><br>Score: %{y}/100<extra></extra>",
        )
    )
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        xaxis=dict(showgrid=False, color="#94a3b8"),
        yaxis=dict(
            range=[0, 105],
            showgrid=True,
            gridcolor="#272f3d",
            zeroline=False,
            color="#94a3b8",
        ),
        margin=dict(l=20, r=20, t=15, b=20),
        height=250,
    )
    return fig
