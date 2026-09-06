"""Reproducible in-project benchmark, NOT a commercial-product comparison.

Run from an installed checkout: python tools/benchmark_dispatch.py --output result.json
The timer covers validated store operations only, excluding setup, HTTP/TLS and login.
"""
import argparse
import json
import platform
import secrets
import shutil
import statistics
import tempfile
import time
import uuid
from pathlib import Path

from openviscera import __version__
from openviscera.demo import Driver
from openviscera.evidence import check_database
from openviscera.store import Store


def run(count=25, repeats=5):
    if not 1 <= count <= 100 or not 1 <= repeats <= 20:
        raise ValueError("Use 1-100 specimens and 1-20 repetitions")
    with tempfile.TemporaryDirectory(prefix="openviscera-benchmark-") as temporary:
        root = Path(temporary)
        source = Store.initialize(root / "base")
        users = {role: source.add_user("synthetic-benchmark", {"username": role, "display_name": "Synthetic " + role,
                  "role": role, "password": secrets.token_urlsafe(24)}) for role in ["examiner", "courier"]}
        lab = source.add_lab("synthetic-benchmark", {"name": "Synthetic laboratory"})
        d = Driver(source, users, lab)
        state = d.new("BENCHMARK-SYNTHETIC")
        for index in range(count):
            state = d.do(state["id"], "collect", {"container_id": f"SYN-{index}", "description": "Synthetic benchmark specimen",
                "quantity": "1", "unit": "container", "preservative": "Entered", "collected_at": d.past, "location": "Room"})
            state = d.do(state["id"], "seal", {"specimen_id": state["specimens"][-1]["id"], "seal_ref": "SYN-SEAL",
                "occurred_at": d.past, "reason": "Synthetic seal"})
        values = [{"specimen_id": sp["id"], "recipient_id": users["courier"]["id"], "occurred_at": d.past,
                   "destination": "Synthetic receiver", "note": "Benchmark dispatch"} for sp in state["specimens"]]
        measurements = {"individual": [], "atomic_batch": []}
        for repeat in range(repeats):
            # Alternate order to reduce systematic warm-cache bias.
            modes = ["individual", "atomic_batch"] if repeat % 2 == 0 else ["atomic_batch", "individual"]
            for mode in modes:
                destination = root / f"{mode}-{repeat}"
                shutil.copytree(source.path, destination)  # Quiescent synthetic test store, not an operational backup.
                store = Store(destination)
                version = state["version"]
                begin = time.perf_counter()
                if mode == "individual":
                    for value in values:
                        result = store.command(users["examiner"], state["id"], "handover", value, version, uuid.uuid4().hex)
                        version = result["case"]["version"]
                else:
                    result = store.batch_handover(users["examiner"], state["id"],
                        {"expected_version": version, "items": values}, uuid.uuid4().hex)
                measurements[mode].append(time.perf_counter() - begin)
                actual = result["case"]
                assert len(actual["transfers"]) == count
                assert actual["version"] == state["version"] + count
                assert all(t["recipient_id"] == users["courier"]["id"] and not t["acknowledged_at"] for t in actual["transfers"])
                assert all(sp["holder_id"] == users["examiner"]["id"] for sp in actual["specimens"])
                check_database(store)  # Full replay and signatures, outside the timed section.
        medians = {k: statistics.median(v) for k, v in measurements.items()}
        return {"version": __version__, "synthetic_only": True, "platform": platform.platform(),
                "python": platform.python_version(), "specimens": count, "repetitions": repeats,
                "scope": "Validated store operations only; no HTTP, TLS, authentication, user interaction or competitor software",
                "seconds": measurements, "median_seconds": medians,
                "individual_over_batch_median_ratio": medians["individual"] / medians["atomic_batch"],
                "events_per_variant": count, "transactions": {"individual": count, "atomic_batch": 1},
                "full_evidence_replay_after_each_variant": True}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--specimens", type=int, default=25)
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = run(args.specimens, args.repeats)
    text = json.dumps(result, indent=2)
    if args.output:
        with args.output.open("x") as output:
            output.write(text + "\n")
    print(text)
