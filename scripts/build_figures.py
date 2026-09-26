"""
Regenerate the plotted figures of the paper in an LNCS-friendly Matplotlib style.

Earlier revisions of the figures embedded fonts that pdftoppm/xpdf
reported as "font mismatch" and rendered a few math tokens with a
fallback CJK glyph set on hosts without DejaVu Serif.  This script pins
the visual style to Springer LNCS/LNNS proceedings:

  * a serif body font (Computer Modern via Matplotlib's mathtext), so
    the figures match the paper's body text at print size;
  * fully embedded Type-3 fonts (pdf.fonttype=3, Matplotlib's default),
    which avoid the "TrueType embedded but declared Type-1" warning of
    the earlier PDFs;
  * Latin-1 characters only in every label;
  * line widths and marker sizes that keep the shrunk figure (about
    9 cm wide in svproc) legible at 100% zoom.

The script reads the CSV files under prototype/results/ and writes

    figures/fig_scalability.pdf     Fig. 4 of the paper
    figures/fig_ftpm_hist.pdf       supplementary plot
    figures/fig_env_comparison.pdf  supplementary plot

Run from any directory:
    python3 scripts/build_figures.py
"""
from __future__ import annotations

import csv
import statistics
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np


# ============================================================
#  LNCS-friendly rc parameters
# ============================================================
plt.rcParams.update({
    # font family: match the paper's serif body text
    "font.family":         "serif",
    "font.serif":          ["cmr10", "Times", "DejaVu Serif"],
    "mathtext.fontset":    "cm",             # Computer Modern math
    "mathtext.default":    "regular",

    # sizes: what looks right after shrinking to a single-column
    # svproc figure (~ 9 cm wide)
    "font.size":           9,
    "axes.titlesize":      9,
    "axes.labelsize":      9,
    "xtick.labelsize":     8,
    "ytick.labelsize":     8,
    "legend.fontsize":     7.5,

    # geometry
    "axes.linewidth":      0.7,
    "grid.linewidth":      0.3,
    "grid.alpha":          0.55,
    "lines.linewidth":     1.1,
    "lines.markersize":    4.5,
    "axes.grid":           True,
    "axes.grid.which":     "major",

    # LNCS: Type-3 fonts, cropped bbox
    "pdf.fonttype":        3,
    "ps.fonttype":         3,
    "savefig.dpi":         300,
    "savefig.bbox":        "tight",
    "figure.dpi":          200,

    # legend styling
    "legend.frameon":      True,
    "legend.framealpha":   0.95,
    "legend.fancybox":     False,
    "legend.edgecolor":    "black",
})

ROOT = Path(__file__).resolve().parents[1]       # repository root
FIG  = ROOT / "figures"
RES  = ROOT / "prototype" / "results"

SB_MOCK  = RES / "sandbox" / "e5_scalability_mock.csv"
WSL_MOCK = RES / "wsl2"    / "e5_scalability_mock.csv"
WSL_SWT  = RES / "wsl2"    / "e5_scalability_swtpm.csv"
FTPM_CSV = RES / "ftpm"    / "ftpm_quote_latency.csv"


def read_sweep(path):
    with open(path) as f:
        rows = list(csv.DictReader(f))
    ks = [int(r["k"]) for r in rows]
    ag = [float(r["aggr_ns"])/1e6     for r in rows]
    vr = [float(r["verifier_ns"])/1e6 for r in rows]
    wr = [int(r["wire_bytes"])        for r in rows]
    return ks, ag, vr, wr


def fig_scalability():
    ks_sb,  ag_sb,  vr_sb,  _ = read_sweep(SB_MOCK)
    ks_wm,  ag_wm,  vr_wm,  _ = read_sweep(WSL_MOCK)
    ks_ws,  ag_ws,  vr_ws,  _ = read_sweep(WSL_SWT)

    fig, (axL, axR) = plt.subplots(1, 2, figsize=(6.4, 2.7))

    common = dict(linewidth=1.1, markersize=4.5, markeredgewidth=0.8)

    # Panel (a): Verifier latency vs k
    axL.plot(ks_sb, vr_sb, marker="o", linestyle="--",
             color="black",         label="mock, sandbox", **common)
    axL.plot(ks_wm, vr_wm, marker="s", linestyle="-",
             color="#333333",       label="mock, WSL2",    **common)
    axL.plot(ks_ws, vr_ws, marker="^", linestyle="-",
             color="#7a7a7a",       label="swtpm, WSL2",   **common)
    axL.set_xscale("log")
    axL.set_yscale("log")
    axL.set_xlabel(r"roster size $k$")
    axL.set_ylabel(r"Verifier accept latency (ms)")
    axL.set_title(r"(a) Verifier: $T_V(k) = c_V + k\,T_{DICE}$")
    axL.legend(loc="upper left")
    axL.set_ylim(0.1, 500)

    # reference lines: 100 ms budget and 194.5 ms fTPM Quote
    axL.axhline(100,   color="black", linestyle=":",  linewidth=0.7, alpha=0.7)
    axL.axhline(194.5, color="black", linestyle="-.", linewidth=0.7, alpha=0.6)
    axL.text(1050, 72,  "100 ms budget",      ha="right",
             fontsize=6.3, alpha=0.80)
    axL.text(1050, 240, "fTPM Quote 194.5 ms", ha="right",
             fontsize=6.3, alpha=0.80)

    # Panel (b): Aggregator latency vs k
    axR.plot(ks_sb, ag_sb, marker="o", linestyle="--",
             color="black",         label="mock, sandbox", **common)
    axR.plot(ks_wm, ag_wm, marker="s", linestyle="-",
             color="#333333",       label="mock, WSL2",    **common)
    axR.plot(ks_ws, ag_ws, marker="^", linestyle="-",
             color="#7a7a7a",       label="swtpm, WSL2",   **common)
    axR.set_xscale("log")
    axR.set_yscale("log")
    axR.set_xlabel(r"roster size $k$")
    axR.set_ylabel(r"Aggregator construction latency (ms)")
    axR.set_title(r"(b) Aggregator: TPM Quote floor $+\;O(k)$")
    axR.legend(loc="lower right")
    axR.set_ylim(0.3, 500)

    fig.tight_layout(w_pad=1.2)
    out = FIG / "fig_scalability.pdf"
    fig.savefig(out); plt.close(fig)
    print(f"wrote {out}")


def fig_ftpm_hist():
    with open(FTPM_CSV) as f:
        xs = np.array([int(r["quote_ns"])/1e6 for r in csv.DictReader(f)])
    fig, ax = plt.subplots(figsize=(4.2, 2.3))
    ax.hist(xs, bins=24, color="#cfcfcf", edgecolor="black", linewidth=0.5)
    ax.axvline(xs.mean(), color="black", linestyle="--", linewidth=0.9,
               label=f"mean = {xs.mean():.1f} ms")
    ax.axvline(np.percentile(xs, 95), color="black", linestyle=":", linewidth=0.9,
               label=f"p95  = {np.percentile(xs, 95):.1f} ms")
    ax.set_xlabel(r"Intel PTT fTPM TPM2_Quote latency (ms)")
    ax.set_ylabel("count")
    ax.set_title(f"fTPM Quote distribution (n = {len(xs)})")
    ax.legend(loc="upper right")
    fig.tight_layout()
    out = FIG / "fig_ftpm_hist.pdf"
    fig.savefig(out); plt.close(fig)
    print(f"wrote {out}")


def fig_env_comparison():
    def read_at(path, field, k_at):
        for r in csv.DictReader(open(path)):
            if int(r["k"]) == k_at:
                return float(r[field]) / 1000.0
        return None

    with open(FTPM_CSV) as f:
        ftpm_us = statistics.mean(int(r["quote_ns"]) for r in csv.DictReader(f)) / 1000.0

    metrics = [
        ("mock verifier k=2",      "verifier_ns", 2,    SB_MOCK, WSL_MOCK),
        ("mock verifier k=100",    "verifier_ns", 100,  SB_MOCK, WSL_MOCK),
        ("mock verifier k=1000",   "verifier_ns", 1000, SB_MOCK, WSL_MOCK),
        ("swtpm aggr k=2",         "aggr_ns",     2,    None,    WSL_SWT),
        ("swtpm aggr k=1000",      "aggr_ns",     1000, None,    WSL_SWT),
        ("fTPM Quote",             None,          0,    None,    None),
    ]

    labels, sandbox, wsl2 = [], [], []
    for name, field, k, sb, wl in metrics:
        labels.append(name)
        if field is None:
            sandbox.append(0.0); wsl2.append(ftpm_us)
        else:
            sandbox.append(read_at(sb, field, k) if sb else 0.0)
            wsl2   .append(read_at(wl, field, k) if wl else 0.0)

    x = np.arange(len(labels)); w = 0.35
    fig, ax = plt.subplots(figsize=(6.4, 2.9))
    ax.bar(x - w/2, sandbox, w, color="#cfcfcf",
           edgecolor="black", linewidth=0.7, label="Sandbox")
    ax.bar(x + w/2, wsl2,    w, color="white",
           edgecolor="black", linewidth=0.7, hatch="///",
           label="WSL2 / Intel PTT")
    ax.set_yscale("log")
    ax.set_ylabel(r"latency ($\mu$s, log)")
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=25, ha="right", fontsize=7)
    ax.legend(loc="upper left")
    ax.set_title("Sandbox vs. WSL2 vs. Intel PTT fTPM")
    for xi, (sb, wl) in enumerate(zip(sandbox, wsl2)):
        for xoff, v in ((-w/2, sb), (w/2, wl)):
            if v > 0:
                ax.text(xi + xoff, v * 1.15, f"{v:.0f}", ha="center",
                        va="bottom", fontsize=6.5)
    fig.tight_layout()
    out = FIG / "fig_env_comparison.pdf"
    fig.savefig(out); plt.close(fig)
    print(f"wrote {out}")


if __name__ == "__main__":
    FIG.mkdir(parents=True, exist_ok=True)
    fig_scalability()
    fig_ftpm_hist()
    fig_env_comparison()
    print("done")
