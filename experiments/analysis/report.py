"""Summarise one experiments/results/<run> directory into summary.md + PNGs.

    python experiments/analysis/report.py experiments/results/<run>

A correlate run needs trials.csv (and ablation.csv from `just replay`);
an overhead run needs latency.csv and resources.csv.
"""

import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import pandas as pd  # noqa: E402

# Correct means the reported sync matches ground truth, either way.
CORRECT = {"hit", "correct-none"}
PLATFORM_NAMESPACES = [
    "kube-system", "istio-system", "istio-ingress", "argocd", "gatekeeper-system",
    "falco", "observability", "correlator", "mail",
]
LAYERS = ["l0-cni", "l1-policy", "l2-mesh", "l3-full"]


def quantiles(s: pd.Series) -> str:
    return f"{s.median():.2f} / {s.quantile(0.95):.2f} / {s.max():.2f}"


def correlate(run: Path) -> list[str]:
    t = pd.read_csv(run / "trials.csv")
    out = ["## Live trials", ""]
    counts = t.pivot_table(index="scenario", columns="outcome", values="trial", aggfunc="count", fill_value=0)
    out += [counts.to_markdown(), ""]
    d = t[t.outcome != "undelivered"]
    out += [
        f"- Trials: {len(t)}, delivered: {len(d)} ({len(d) / len(t):.1%})",
        f"- Attribution correct: {d.outcome.isin(CORRECT).mean():.1%}",
        f"- Falco detection (attack to alert time), s, median / p95 / max: {quantiles(d.detect_s)}",
        f"- Delivery (attack to incident visible), s: {quantiles(d.deliver_s)}",
        f"- Final incident (alert to last trace refresh), s: {quantiles(d.final_s)}",
        f"- Planted-trace recall, mean: {d.trace_recall.mean():.3f}",
        f"- Planted error trace captured: {d.error_captured.mean():.1%}",
        "",
    ]

    ablation = run / "ablation.csv"
    if not ablation.exists():
        return out + ["(no ablation.csv; run `just replay <run>`)", ""]
    a = pd.read_csv(ablation)
    a = a[a.outcome != "undelivered"]
    a["correct"] = a.outcome.isin(CORRECT)

    acc = a.groupby(["scenario", "lookback_s"]).correct.mean().unstack("scenario")
    ax = acc.plot(marker="o", logx=True, figsize=(7, 4))
    ax.set(xlabel="deploy lookback (s)", ylabel="attribution correct", title="Attribution vs lookback", ylim=(-0.05, 1.05))
    ax.figure.tight_layout()
    ax.figure.savefig(run / "ablation-lookback.png", dpi=150)
    plt.close(ax.figure)

    tr = a.groupby("span_s")[["trace_recall", "error_captured"]].mean()
    ax = tr.plot(marker="o", figsize=(7, 4))
    ax.set(xlabel="trace half-window (s)", ylabel="rate", title="Trace capture vs span", ylim=(-0.05, 1.05))
    ax.figure.tight_layout()
    ax.figure.savefig(run / "ablation-span.png", dpi=150)
    plt.close(ax.figure)

    out += ["## Window ablation (replayed)", "", "Attribution correct by lookback:", "", acc.round(3).to_markdown(), "",
            "Trace capture by span:", "", tr.round(3).to_markdown(), "",
            "![](ablation-lookback.png)", "", "![](ablation-span.png)", ""]
    return out


def overhead(run: Path) -> list[str]:
    lat = pd.read_csv(run / "latency.csv")
    res = pd.read_csv(run / "resources.csv")
    out = ["## Request latency (k6, ms)", ""]
    g = lat.groupby(["layer", "falco"])[["p50_ms", "p95_ms", "p99_ms", "failed_rate"]].agg(["mean", "std"])
    out += [g.round(3).to_markdown(), ""]

    p = lat.groupby(["layer", "falco"]).p99_ms.mean().unstack("falco").reindex(LAYERS)
    ax = p.plot.bar(figsize=(7, 4), rot=0)
    ax.set(ylabel="p99 latency (ms)", title="p99 latency by layer, Falco on/off")
    ax.figure.tight_layout()
    ax.figure.savefig(run / "latency-p99.png", dpi=150)
    plt.close(ax.figure)

    # Workload cost: app and sidecar containers in each layer's namespace.
    res["layer_ns"] = "bench-" + res.layer
    wl = res[res.namespace == res.layer_ns].groupby(["layer", "falco", "role"])[["cpu_cores", "mem_mib"]].mean()
    platform = res[res.namespace.isin(PLATFORM_NAMESPACES)].groupby(["namespace", "falco"])[["cpu_cores", "mem_mib"]].mean()
    out += ["## Workload namespace cost (mean over reps)", "", wl.round(4).to_markdown(), "",
            "## Platform component cost during load (mean over cells)", "", platform.round(4).to_markdown(), "",
            "![](latency-p99.png)", ""]
    return out


def main() -> None:
    run = Path(sys.argv[1])
    lines = [f"# {run.name}", ""]
    if (run / "trials.csv").exists():
        lines += correlate(run)
    if (run / "latency.csv").exists():
        lines += overhead(run)
    (run / "summary.md").write_text("\n".join(lines))
    print(run / "summary.md")


if __name__ == "__main__":
    main()
