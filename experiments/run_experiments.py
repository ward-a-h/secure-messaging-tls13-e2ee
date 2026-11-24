"""
run_experiments.py

Runs the complete experimental evaluation automatically and saves the
results as CSV and Markdown files.

For every network condition, every security mode and every run, the script:
  1. applies the network condition to the transit link with tc netem
  2. starts the relay server in the srv namespace
  3. starts the echo bot in the c2 namespace
  4. runs bench_client.py in the c1 namespace and collects its JSON output
  5. stops the echo bot and the server

Network conditions (applied to the transit link between r1 and r2):
  baseline   no impairment
  rtt_20     +20 ms round trip time
  rtt_100    +100 ms round trip time
  loss_2     2% packet loss in each direction
  loss_5     5% packet loss in each direction

Security modes:
  plain      no TLS, no end-to-end encryption
  tls        TLS 1.3 only
  tls_e2e    TLS 1.3 + end-to-end encryption

Each combination is repeated --runs times (default 3). Inside every run the
bench client opens --handshakes connections and sends --messages messages,
and the run is summarised by its mean values. The final summary reports, for
each metric, the mean of the run means and their spread (standard deviation,
minimum and maximum across runs).

Output (in experiments/results/):
  raw_runs.csv      one row per run
  summary.csv       one row per condition, mode and metric
  summary.md        the same summary as readable tables
  environment.txt   machine and software details, for reproducibility

Usage (from the repository root, with the topology already set up):
    sudo .venv/bin/python experiments/run_experiments.py
    sudo .venv/bin/python experiments/run_experiments.py --runs 3 --handshakes 20 --messages 50
    sudo .venv/bin/python experiments/run_experiments.py --conditions baseline rtt_100
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import platform
import shutil
import statistics
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = REPO_ROOT / "experiments" / "results"
NETEM_SCRIPT = REPO_ROOT / "topology" / "netem.sh"
PYTHON = sys.executable


@dataclass(frozen=True)
class Condition:
    name: str
    label: str
    rtt_ms: int
    loss_percent: float


CONDITIONS = {
    "baseline": Condition("baseline", "No impairment", 0, 0),
    "rtt_20": Condition("rtt_20", "+20 ms RTT", 20, 0),
    "rtt_100": Condition("rtt_100", "+100 ms RTT", 100, 0),
    "loss_2": Condition("loss_2", "2% loss", 0, 2),
    "loss_5": Condition("loss_5", "5% loss", 0, 5),
}

# Command line flags for the server and the clients in each security mode.
MODES = {
    "plain": {"server": ["--plain"], "client": ["--plain", "--no-e2e"]},
    "tls": {"server": [], "client": ["--no-e2e"]},
    "tls_e2e": {"server": [], "client": []},
}

# Metrics recorded per run: (column name, path into the bench JSON, unit)
METRICS = [
    ("tcp_setup_ms", ("handshake", "tcp_ms", "mean"), "ms"),
    ("tls_handshake_ms", ("handshake", "tls_ms", "mean"), "ms"),
    ("total_setup_ms", ("handshake", "total_ms", "mean"), "ms"),
    ("message_rtt_ms", ("message_rtt_ms", "mean"), "ms"),
    ("message_rtt_median_ms", ("message_rtt_ms", "median"), "ms"),
    ("wire_bytes_per_message", ("wire_bytes_per_message",), "bytes"),
]


def log(text: str) -> None:
    print(f"[experiments] {text}", flush=True)


def fail(text: str) -> None:
    print(f"[experiments] ERROR: {text}", file=sys.stderr)
    sys.exit(1)


def in_namespace(namespace: str, *command: str) -> list[str]:
    return ["ip", "netns", "exec", namespace, *command]


def set_condition(condition: Condition) -> None:
    if condition.rtt_ms == 0 and condition.loss_percent == 0:
        subprocess.run([str(NETEM_SCRIPT), "clear"], check=True, stdout=subprocess.DEVNULL)
    else:
        subprocess.run([str(NETEM_SCRIPT), "set", "--rtt", str(condition.rtt_ms),
                        "--loss", f"{condition.loss_percent:g}"], check=True, stdout=subprocess.DEVNULL)


def start_and_wait(command: list[str], ready_text: str, timeout: float = 15.0) -> subprocess.Popen:
    """Start a background process and wait until it prints ready_text."""
    process = subprocess.Popen(command, cwd=REPO_ROOT, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, text=True)
    deadline = time.monotonic() + timeout
    assert process.stdout is not None
    while time.monotonic() < deadline:
        line = process.stdout.readline()
        if not line:
            break
        if ready_text in line:
            return process
    process.kill()
    fail(f"process did not become ready: {' '.join(command)}")
    raise SystemExit(1)


def stop(process: subprocess.Popen) -> None:
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()


def run_once(mode: str, args: argparse.Namespace) -> dict:
    flags = MODES[mode]
    server = start_and_wait(
        in_namespace("srv", PYTHON, "src/server.py", "--log-level", "WARNING", *flags["server"]),
        "Relay server listening")
    echo = None
    try:
        echo = start_and_wait(in_namespace("c2", PYTHON, "src/echo_bot.py", *flags["client"]), "[echo] Ready")
        result = subprocess.run(
            in_namespace("c1", PYTHON, "src/bench_client.py", "--mode", mode,
                         "--handshakes", str(args.handshakes), "--messages", str(args.messages)),
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=args.run_timeout)
        output = json.loads(result.stdout.strip().splitlines()[-1])
        if "error" in output:
            fail(f"bench client failed in mode {mode}: {output['error']}")
        return output
    finally:
        if echo is not None:
            stop(echo)
        stop(server)


def extract(result: dict, path: tuple[str, ...]) -> float:
    value = result
    for key in path:
        value = value[key]
    return float(value)


def summarise_runs(rows: list[dict]) -> list[dict]:
    summary = []
    for condition in dict.fromkeys(row["condition"] for row in rows):
        for mode in MODES:
            subset = [row for row in rows if row["condition"] == condition and row["mode"] == mode]
            if not subset:
                continue
            for metric, _, unit in METRICS:
                values = [row[metric] for row in subset]
                summary.append({
                    "condition": condition,
                    "condition_label": CONDITIONS[condition].label,
                    "mode": mode,
                    "metric": metric,
                    "unit": unit,
                    "runs": len(values),
                    "mean": statistics.fmean(values),
                    "stdev": statistics.stdev(values) if len(values) > 1 else 0.0,
                    "min": min(values),
                    "max": max(values),
                })
    return summary


def write_csv(path: Path, rows: list[dict]) -> None:
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        for row in rows:
            writer.writerow({key: f"{value:.4f}" if isinstance(value, float) else value
                             for key, value in row.items()})


def write_markdown(path: Path, summary: list[dict], args: argparse.Namespace) -> None:
    titles = {
        "tcp_setup_ms": "TCP connection setup (ms)",
        "tls_handshake_ms": "TLS 1.3 handshake on top of TCP (ms)",
        "total_setup_ms": "Total time before the first message can be sent (ms)",
        "message_rtt_ms": "Message round-trip time through the relay (ms, mean)",
        "message_rtt_median_ms": "Message round-trip time through the relay (ms, median)",
        "wire_bytes_per_message": "Bytes on the wire per message round trip",
    }
    conditions = list(dict.fromkeys(row["condition"] for row in summary))
    lines = [
        "# Experiment results",
        "",
        f"Each value is the mean of {args.runs} runs, followed by the standard deviation across runs.",
        f"Every run used {args.handshakes} connections and {args.messages} messages.",
        "",
    ]
    for metric, title in titles.items():
        lines += [f"## {title}", "", "| Condition | plain | tls | tls_e2e |", "|---|---|---|---|"]
        for condition in conditions:
            cells = []
            for mode in MODES:
                match = [row for row in summary if row["condition"] == condition
                         and row["mode"] == mode and row["metric"] == metric]
                cells.append(f"{match[0]['mean']:.2f} ± {match[0]['stdev']:.2f}" if match else "n/a")
            lines.append(f"| {CONDITIONS[condition].label} | " + " | ".join(cells) + " |")
        lines.append("")
    path.write_text("\n".join(lines))


def write_environment(path: Path, args: argparse.Namespace) -> None:
    def command_output(command: list[str]) -> str:
        try:
            return subprocess.run(command, capture_output=True, text=True, check=False).stdout.strip()
        except OSError:
            return "unavailable"

    cpu = "unknown"
    cpuinfo = Path("/proc/cpuinfo")
    if cpuinfo.exists():
        for line in cpuinfo.read_text().splitlines():
            if line.startswith("model name"):
                cpu = line.split(":", 1)[1].strip()
                break
    memory = "unknown"
    meminfo = Path("/proc/meminfo")
    if meminfo.exists():
        kb = int(meminfo.read_text().split()[1])
        memory = f"{kb / 1024 / 1024:.1f} GB"

    path.write_text("\n".join([
        f"Date:            {datetime.now().isoformat(timespec='seconds')}",
        f"CPU:             {cpu}",
        f"CPU cores:       {os.cpu_count()}",
        f"Memory:          {memory}",
        f"Kernel:          {platform.release()}",
        f"OS:              {command_output(['lsb_release', '-ds']) or platform.platform()}",
        f"Python:          {platform.python_version()}",
        f"OpenSSL:         {__import__('ssl').OPENSSL_VERSION}",
        f"PyNaCl:          {__import__('importlib.metadata').metadata.version('pynacl')}",
        f"tc:              {command_output(['tc', '-V'])}",
        f"Runs:            {args.runs}",
        f"Handshakes/run:  {args.handshakes}",
        f"Messages/run:    {args.messages}",
        f"Conditions:      {', '.join(args.conditions)}",
        "",
    ]))


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the full experimental evaluation.")
    parser.add_argument("--runs", type=int, default=3, help="repetitions per condition and mode (default: 3)")
    parser.add_argument("--handshakes", type=int, default=20, help="connections per run (default: 20)")
    parser.add_argument("--messages", type=int, default=50, help="messages per run (default: 50)")
    parser.add_argument("--conditions", nargs="+", default=list(CONDITIONS), choices=list(CONDITIONS),
                        help="network conditions to test (default: all)")
    parser.add_argument("--run-timeout", type=float, default=300.0, help="seconds allowed for one run")
    return parser.parse_args()


def main() -> None:
    args = parse_arguments()
    if os.geteuid() != 0:
        fail("Run as root: sudo .venv/bin/python experiments/run_experiments.py")
    namespaces = subprocess.run(["ip", "netns", "list"], capture_output=True, text=True).stdout
    if "srv" not in namespaces:
        fail("Topology not found. Run: sudo ./topology/setup.sh")
    if not (REPO_ROOT / "certs" / "server.crt").exists():
        fail("Certificate not found. Run: ./scripts/generate_cert.sh")

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    total = len(args.conditions) * len(MODES) * args.runs
    log(f"Starting {total} runs: {len(args.conditions)} conditions x {len(MODES)} modes x {args.runs} runs")

    rows: list[dict] = []
    done = 0
    try:
        for condition_name in args.conditions:
            condition = CONDITIONS[condition_name]
            set_condition(condition)
            log(f"Condition: {condition.label}")
            # Modes are interleaved within each repetition, so slow drifts in
            # the machine's load affect all modes equally.
            for run in range(1, args.runs + 1):
                for mode in MODES:
                    result = run_once(mode, args)
                    row = {"condition": condition_name, "mode": mode, "run": run}
                    for metric, path, _ in METRICS:
                        row[metric] = extract(result, path)
                    rows.append(row)
                    done += 1
                    log(f"  [{done:>2}/{total}] {mode:<8} run {run}: setup {row['total_setup_ms']:.2f} ms, "
                        f"message RTT {row['message_rtt_ms']:.2f} ms, {row['wire_bytes_per_message']:.0f} bytes/message")
    finally:
        subprocess.run([str(NETEM_SCRIPT), "clear"], stdout=subprocess.DEVNULL, check=False)
        log("Network impairment removed")

    summary = summarise_runs(rows)
    write_csv(RESULTS_DIR / "raw_runs.csv", rows)
    write_csv(RESULTS_DIR / "summary.csv", summary)
    write_markdown(RESULTS_DIR / "summary.md", summary, args)
    write_environment(RESULTS_DIR / "environment.txt", args)

    # Files were written as root, so give them back to the user who ran sudo.
    owner = os.environ.get("SUDO_USER")
    if owner:
        for path in RESULTS_DIR.iterdir():
            shutil.chown(path, user=owner, group=owner)

    log(f"Results saved in {RESULTS_DIR.relative_to(REPO_ROOT)}/")


if __name__ == "__main__":
    main()
