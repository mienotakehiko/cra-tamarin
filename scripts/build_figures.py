"""
Regenerate the paper's figures with the U1/U2/U3 measurement drop.

New figures:
    fig_scalability.pdf   -- k-sweep on sandbox and WSL2, mock and swtpm.
    fig_ftpm_hist.pdf     -- fTPM Quote latency histogram (Intel PTT).
    fig_env_comparison.pdf -- updated: adds fTPM column and E6 concurrency.
"""
from __future__ import annotations

import csv
import statistics
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

plt.rcParams.update({
    "font.family": "serif", "font.size": 9,
    "axes.linewidth": 0.7, "axes.grid": True,
    "grid.linewidth": 0.3, "grid.alpha": 0.6,
    "legend.frameon": True, "legend.fontsize": 8,
    "figure.dpi": 200, "savefig.dpi": 300,
    "savefig.bbox": "tight", "pdf.fonttype": 42,
})

ROOT = Path("/home/user/workspace/bce27")
FIG = ROOT / "figures"

SB_MOCK  = ROOT / "prototype" / "results" / "e5_scalability_mock.csv"
WSL_MOCK = ROOT / "prototype" / "results_wsl2" / "e5_scalability_mock.csv"
WSL_SWT  = ROOT / "prototype" / "results_wsl2" / "e5_scalability_swtpm.csv"
FTPM_CSV = ROOT / "prototype" / "results_ftpm" / "ftpm_quote_latency.csv"

def read_sweep(path):
    with open(path) as f:
        rows = list(csv.DictReader(f))
    ks = [int(r["k"]) for r in rows]
    ag = [float(r["aggr_ns"])/1e6 for r in rows]
    vr = [float(r["verifier_ns"])/1e6 for r in rows]
    wr = [int(r["wire_bytes"]) for r in rows]
    return ks, ag, vr, wr

def fig_scalability():
    ks_sb,  ag_sb,  vr_sb,  wr_sb  = read_sweep(SB_MOCK)
    ks_wm,  ag_wm,  vr_wm,  wr_wm  = read_sweep(WSL_MOCK)
    ks_ws,  ag_ws,  vr_ws,  wr_ws  = read_sweep(WSL_SWT)

    fig, (axL, axR) = plt.subplots(1, 2, figsize=(6.2, 2.6))

    # Left panel: verifier latency vs k, log-log
    axL.plot(ks_sb, vr_sb, marker="o", linestyle="--",
             color="black",   label="mock (sandbox, KVM 1 vCPU)")
    axL.plot(ks_wm, vr_wm, marker="s", linestyle="-",
             color="#333333", label="mock (WSL2, i7-13700H)")
    axL.plot(ks_ws, vr_ws, marker="^", linestyle="-",
             color="#888888", label="swtpm (WSL2, i7-13700H)")
    axL.set_xscale("log"); axL.set_yscale("log")
    axL.set_xlabel("roster size $k$")
    axL.set_ylabel("Verifier atomic-accept latency (ms)")
    axL.set_title("Verifier scales linearly in $k$", fontsize=9)
    axL.legend(loc="upper left")
    # 100 ms reference line
    axL.axhline(100, color="red", linestyle=":", linewidth=0.7)
    axL.text(1000, 130, "100 ms budget", color="red", fontsize=7, ha="right")

    # Right panel: Aggregator latency vs k
    axR.plot(ks_sb, ag_sb, marker="o", linestyle="--",
             color="black",   label="mock (sandbox)")
    axR.plot(ks_wm, ag_wm, marker="s", linestyle="-",
             color="#333333", label="mock (WSL2)")
    axR.plot(ks_ws, ag_ws, marker="^", linestyle="-",
             color="#888888", label="swtpm (WSL2)")
    axR.set_xscale("log"); axR.set_yscale("log")
    axR.set_xlabel("roster size $k$")
    axR.set_ylabel("Aggregator construction latency (ms)")
    axR.set_title("Aggregator: fixed Quote cost + $O(k)$", fontsize=9)
    axR.legend(loc="lower right")

    fig.tight_layout()
    out = FIG / "fig_scalability.pdf"
    fig.savefig(out); plt.close(fig)
    print(f"wrote {out}")


def fig_ftpm_hist():
    with open(FTPM_CSV) as f:
        xs = np.array([int(r["quote_ns"])/1e6 for r in csv.DictReader(f)])
    fig, ax = plt.subplots(figsize=(4.2, 2.3))
    ax.hist(xs, bins=24, color="#cccccc", edgecolor="black", linewidth=0.5)
    ax.axvline(xs.mean(), color="black", linestyle="--", linewidth=0.9,
               label=f"mean = {xs.mean():.1f} ms")
    ax.axvline(np.percentile(xs, 95), color="black", linestyle=":", linewidth=0.9,
               label=f"p95  = {np.percentile(xs, 95):.1f} ms")
    ax.set_xlabel("Intel PTT fTPM TPM2_Quote latency (ms)")
    ax.set_ylabel("count")
    ax.set_title(f"fTPM Quote distribution ($n={len(xs)}$)", fontsize=9)
    ax.legend(loc="upper right")
    fig.tight_layout()
    out = FIG / "fig_ftpm_hist.pdf"
    fig.savefig(out); plt.close(fig)
    print(f"wrote {out}")


def fig_env_comparison():
    """Three-way bar chart summarising sandbox, WSL2 (mock/swtpm) and fTPM."""
    def read_agg_stat(path, field, k_at=2):
        # Return mean at k=k_at as microseconds
        for r in csv.DictReader(open(path)):
            if int(r["k"]) == k_at:
                return float(r[field]) / 1000.0
        return None

    with open(FTPM_CSV) as f:
        ftpm_ms = statistics.mean(int(r["quote_ns"]) for r in csv.DictReader(f)) / 1e6

    metrics = [
        ("E5 mock AIK sign (k=2)",    "aggr_ns",     2, "sandbox", "wsl2"),
        ("E5 mock verifier (k=2)",    "verifier_ns", 2, "sandbox", "wsl2"),
        ("E5 swtpm AIK sign (k=2)",   "aggr_ns",     2, None,      "wsl2sw"),
        ("E5 mock verifier (k=100)",  "verifier_ns", 100, "sandbox", "wsl2"),
        ("E5 mock verifier (k=1000)", "verifier_ns", 1000, "sandbox", "wsl2"),
        ("fTPM Quote (Intel PTT)",    "ftpm",        0,   None,      "ftpm"),
    ]

    labels, sandbox_vals, wsl2_vals = [], [], []
    for lab, field, k, sb, wl in metrics:
        labels.append(lab)
        if field == "ftpm":
            sandbox_vals.append(0.0)
            wsl2_vals.append(ftpm_ms * 1000.0)  # us
        else:
            src_sb = SB_MOCK if sb == "sandbox" else None
            src_wl = (WSL_MOCK if wl == "wsl2" else
                      WSL_SWT  if wl == "wsl2sw" else None)
            sandbox_vals.append(read_agg_stat(src_sb, field, k) if src_sb else 0.0)
            wsl2_vals.append(read_agg_stat(src_wl, field, k) if src_wl else 0.0)

    x = np.arange(len(labels)); w = 0.35
    fig, ax = plt.subplots(figsize=(6.4, 2.9))
    ax.bar(x - w/2, sandbox_vals, w, color="#cccccc",
           edgecolor="black", linewidth=0.7, label="Sandbox")
    ax.bar(x + w/2, wsl2_vals,    w, color="white",
           edgecolor="black", linewidth=0.7, hatch="///",
           label="WSL2 / Intel PTT")
    ax.set_yscale("log")
    ax.set_ylabel("latency ($\\mu$s, log)")
    ax.set_xticks(x); ax.set_xticklabels(labels, rotation=25, ha="right", fontsize=7)
    ax.legend(loc="upper left")
    ax.set_title("Sandbox vs.\\ WSL2 reproduction; rightmost bar is Intel PTT fTPM Quote",
                 fontsize=9)
    for xi, (sb, wl) in enumerate(zip(sandbox_vals, wsl2_vals)):
        for xoff, v in ((-w/2, sb), (w/2, wl)):
            if v > 0:
                ax.text(xi + xoff, v*1.15, f"{v:.0f}", ha="center", va="bottom",
                        fontsize=6.5)
    fig.tight_layout()
    out = FIG / "fig_env_comparison.pdf"
    fig.savefig(out); plt.close(fig)
    print(f"wrote {out}")


if __name__ == "__main__":
    fig_scalability()
    fig_ftpm_hist()
    fig_env_comparison()
    print("done")
