"""Registry-hive charts; parsing, counting and lookups stay in SQL."""

import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
from vgi_notebooks import finish

SOURCE = (
    "Synthetic Registry fixtures · VGI Windows Registry Hives v0.4.0 · No transaction logs supplied"
)


def plot_audit(audit):
    fig, ax = plt.subplots(figsize=(12, 7.1))
    colors = {
        "Clean header": "#267358",
        "Dirty header, no logs": "#c57b40",
        "Malformed header": "#956f94",
        "Empty input": "#6b7b88",
        "Missing input": "#8d9690",
    }
    for i, r in enumerate(audit.itertuples()):
        ax.scatter(0, i, s=180, color=colors[r.input_state], marker="s")
        size = (
            "No supplied bytes"
            if pd.isna(r.supplied_bytes)
            else f"{int(r.supplied_bytes):,} supplied bytes"
        )
        ax.text(0.18, i, r.input_state, va="center", fontsize=12, color="#253d31")
        ax.text(2.25, i, size, va="center", fontsize=11, color="#52675a")
    ax.set_yticks(range(len(audit)), audit.input_id)
    ax.set_ylim(len(audit) - 0.5, -0.5)
    ax.set_xlim(-0.15, 3.8)
    ax.set_xticks([])
    ax.grid(False)
    for spine in ax.spines.values():
        spine.set_visible(False)
    finish(
        fig,
        "Every supplied input remains in view",
        "Header state is independent of deleted-record recovery",
        SOURCE,
        name="input-audit",
    )


def plot_recovery(summary, RECOVER_DELETED):
    fig, ax = plt.subplots(figsize=(12, 7.4))
    x = np.arange(len(summary))
    width = 0.32
    for shift, col, label, color in [
        (-width / 2, "allocated_value_rows", "Allocated value rows", "#267358"),
        (width / 2, "recovered_value_rows", "Recovered rows", "#c57b40"),
    ]:
        bars = ax.bar(x + shift, summary[col], width, label=label, color=color)
        ax.bar_label(bars, padding=5, fontsize=12)
    ax.set_xticks(x, summary.input_id)
    ax.set_ylabel("Returned value rows · Count")
    ax.set_ylim(
        0,
        max(1, float(summary[["allocated_value_rows", "recovered_value_rows"]].max().max())) * 1.3,
    )
    ax.yaxis.set_major_locator(plt.MaxNLocator(integer=True))
    ax.grid(axis="x", visible=False)
    fig.legend(
        *ax.get_legend_handles_labels(),
        loc="lower left",
        bbox_to_anchor=(0.10, 0.77),
        ncol=2,
        frameon=False,
    )
    finish(
        fig,
        "Recovered rows need their own interpretation",
        f"Deleted recovery {'enabled' if RECOVER_DELETED else 'disabled'} · Readable hives only; no log replay",
        SOURCE,
        name=f"recovery-{RECOVER_DELETED}",
    )


def plot_lookup_scope(reference, selected):
    fig, ax = plt.subplots(figsize=(11.5, 5.2))
    for i, row in enumerate(reference.itertuples()):
        if row.key_label == selected:
            ax.axhspan(i - 0.34, i + 0.34, color="#EBF1EB", zorder=0)
        if row.present:
            ax.scatter([row.value_count], [i], s=105, color="#27745B", zorder=3)
            ax.annotate(
                f"{int(row.value_count)} values",
                (row.value_count, i),
                xytext=(10, 0),
                textcoords="offset points",
                va="center",
                color="#27745B",
            )
        else:
            ax.text(0.12, i, "Not found in this hive", va="center", color="#69766E")
    ax.set_yticks(range(len(reference)), reference.key_label)
    ax.set_ylim(len(reference) - 0.5, -0.5)
    ax.set_xlim(0, max(6.5, float(reference.value_count.max()) + 1.5))
    ax.set_xlabel("Values recorded on a present key · Count")
    ax.set_xticks(range(6))
    ax.grid(axis="y", visible=False)
    found = int(reference.present.sum())
    finish(
        fig,
        f"{found} of {len(reference)} reference keys is present in this fixture",
        f"SOFTWARE reference scope · {selected} highlighted · absent keys have no plotted value count",
        SOURCE,
        name=f"lookup-scope-{selected}",
    )
