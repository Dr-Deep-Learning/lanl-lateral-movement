"""Shared chart style: reference palette (validated), recessive axes, diverging blue<->gray<->red."""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.colors import LinearSegmentedColormap

SURFACE = "#fcfcfb"
INK, INK2, MUTED, GRID = "#1a1a19", "#4a4a47", "#6f6f6b", "#e6e5e1"
SERIES = ["#2a78d6", "#eb6834"]  # categorical slots 1-2 (blue, orange) of the reference palette
DIVERGING = LinearSegmentedColormap.from_list(
    "div", ["#104281", "#3987e5", "#9ec5f4", "#f0efec", "#f2aaa9", "#e34948", "#9e2423"])


def setup():
    plt.rcParams.update({
        "figure.facecolor": SURFACE, "axes.facecolor": SURFACE, "savefig.facecolor": SURFACE,
        "text.color": INK, "axes.labelcolor": INK2, "xtick.color": MUTED, "ytick.color": MUTED,
        "axes.edgecolor": GRID, "axes.grid": False, "font.size": 9, "axes.titlesize": 11,
        "axes.titleweight": "bold", "axes.titlelocation": "left", "axes.spines.top": False,
        "axes.spines.right": False, "lines.linewidth": 2})
