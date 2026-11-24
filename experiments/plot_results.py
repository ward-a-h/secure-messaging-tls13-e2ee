"""
plot_results.py

Draws the figures for the report from experiments/results/summary.csv.

Figures (saved in experiments/plots/):
  connection_setup.png   time before the first message can be sent, per condition
  message_rtt.png        message round-trip time through the relay, per condition
  wire_bytes.png         bytes on the wire per message round trip, per mode

Each network condition gets its own panel with its own vertical scale,
because the values range from fractions of a millisecond (no impairment) to
over a hundred milliseconds (+100 ms RTT). Bars show the mean of the runs and
error bars show the standard deviation across runs. Every bar carries its
value as a label, so the figures can be read without relying on colour.

Usage (from the repository root, after run_experiments.py):
    python experiments/plot_results.py

Requires: matplotlib
"""

from __future__ import annotations

import csv
import sys
from pathlib import Path

try:
    import matplotlib
    matplotlib.use("Agg")  # render to files, no display needed
    import matplotlib.pyplot as plt
except ImportError:
    sys.exit("matplotlib is not installed. Run: pip install matplotlib")

REPO_ROOT = Path(__file__).resolve().parent.parent
SUMMARY_FILE = REPO_ROOT / "experiments" / "results" / "summary.csv"
PLOTS_DIR = REPO_ROOT / "experiments" / "plots"

MODES = ["plain", "tls", "tls_e2e"]
MODE_LABELS = {"plain": "Plaintext TCP", "tls": "TLS 1.3", "tls_e2e": "TLS 1.3 + end-to-end"}
# Colour-blind safe categorical palette, validated for these three slots.
MODE_COLOURS = {"plain": "#2a78d6", "tls": "#eb6834", "tls_e2e": "#1baf7a"}

TEXT_PRIMARY = "#0b0b0b"
TEXT_SECONDARY = "#52514e"
GRID = "#e4e3df"
SURFACE = "#fcfcfb"


def load_summary() -> list[dict]:
    if not SUMMARY_FILE.exists():
        sys.exit(f"{SUMMARY_FILE.relative_to(REPO_ROOT)} not found. Run experiments/run_experiments.py first.")
    with SUMMARY_FILE.open() as handle:
        rows = list(csv.DictReader(handle))
    for row in rows:
        for key in ("mean", "stdev", "min", "max"):
            row[key] = float(row[key])
    return rows


def style_axes(axes) -> None:
    axes.set_facecolor(SURFACE)
    for side in ("top", "right", "left"):
        axes.spines[side].set_visible(False)
    axes.spines["bottom"].set_color(TEXT_SECONDARY)
    axes.tick_params(colors=TEXT_SECONDARY, labelsize=8, length=0)
    axes.yaxis.grid(True, color=GRID, linewidth=0.8)
    axes.set_axisbelow(True)


def value_label(value: float) -> str:
    if value >= 100:
        return f"{value:.0f}"
    if value >= 10:
        return f"{value:.1f}"
    return f"{value:.2f}"


def bar_panel(axes, rows: list[dict], title: str, unit: str) -> None:
    """Three bars, one per security mode, with error bars and value labels."""
    positions = range(len(MODES))
    means = [next(r["mean"] for r in rows if r["mode"] == mode) for mode in MODES]
    errors = [next(r["stdev"] for r in rows if r["mode"] == mode) for mode in MODES]

    axes.bar(positions, means, width=0.72, color=[MODE_COLOURS[m] for m in MODES],
             edgecolor=SURFACE, linewidth=2, yerr=errors,
             error_kw={"ecolor": TEXT_SECONDARY, "elinewidth": 1, "capsize": 3})
    top = max(m + e for m, e in zip(means, errors)) or 1.0
    for x, (mean, error) in enumerate(zip(means, errors)):
        axes.text(x, mean + error + top * 0.03, value_label(mean), ha="center", va="bottom",
                  fontsize=8, color=TEXT_PRIMARY)
    axes.set_ylim(0, top * 1.22)
    axes.set_xticks(list(positions), ["Plain", "TLS", "TLS+E2E"])
    axes.set_title(title, fontsize=9, color=TEXT_PRIMARY, pad=6)
    axes.set_ylabel(unit, fontsize=8, color=TEXT_SECONDARY)
    style_axes(axes)


def per_condition_figure(summary: list[dict], metric: str, title: str, unit: str, filename: str) -> None:
    conditions = list(dict.fromkeys(r["condition"] for r in summary))
    figure, axes_list = plt.subplots(1, len(conditions), figsize=(2.3 * len(conditions), 3.0),
                                     facecolor=SURFACE, squeeze=False)
    for axes, condition in zip(axes_list[0], conditions):
        rows = [r for r in summary if r["condition"] == condition and r["metric"] == metric]
        bar_panel(axes, rows, rows[0]["condition_label"], unit)
    add_legend_and_title(figure, title)
    save(figure, filename)


def wire_bytes_figure(summary: list[dict]) -> None:
    rows = [r for r in summary if r["condition"] == "baseline" and r["metric"] == "wire_bytes_per_message"]
    if not rows:
        return
    figure, axes = plt.subplots(figsize=(4.6, 3.2), facecolor=SURFACE)
    bar_panel(axes, rows, "No impairment", "bytes")
    plain = next(r["mean"] for r in rows if r["mode"] == "plain")
    # Annotate the extra bytes compared with plaintext under each secured bar.
    for x, mode in enumerate(MODES[1:], start=1):
        extra = next(r["mean"] for r in rows if r["mode"] == mode) - plain
        axes.text(x, plain * 0.08, f"+{extra:.0f} B\n(+{extra / plain * 100:.0f}%)", ha="center",
                  va="bottom", fontsize=7.5, color=TEXT_PRIMARY, fontweight="bold")
    add_legend_and_title(figure, "Bytes on the wire per message round trip")
    save(figure, "wire_bytes.png")


def add_legend_and_title(figure, title: str) -> None:
    handles = [plt.Rectangle((0, 0), 1, 1, color=MODE_COLOURS[m]) for m in MODES]
    figure.legend(handles, [MODE_LABELS[m] for m in MODES], loc="upper center", ncol=3,
                  frameon=False, fontsize=8, bbox_to_anchor=(0.5, 0.945), labelcolor=TEXT_PRIMARY)
    figure.suptitle(title, fontsize=11, color=TEXT_PRIMARY, y=0.99)
    figure.tight_layout(rect=(0, 0, 1, 0.92))


def save(figure, filename: str) -> None:
    PLOTS_DIR.mkdir(parents=True, exist_ok=True)
    path = PLOTS_DIR / filename
    figure.savefig(path, dpi=200, facecolor=SURFACE)
    plt.close(figure)
    print(f"[plots] Saved {path.relative_to(REPO_ROOT)}")


def main() -> None:
    summary = load_summary()
    per_condition_figure(summary, "total_setup_ms",
                         "Time before the first message can be sent (TCP + TLS handshake)",
                         "ms", "connection_setup.png")
    per_condition_figure(summary, "message_rtt_ms",
                         "Message round-trip time through the relay (mean of runs)",
                         "ms", "message_rtt.png")
    wire_bytes_figure(summary)


if __name__ == "__main__":
    main()
