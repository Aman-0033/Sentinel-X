"""Generate benchmark network flow dataset for SENTINEL-X intrusion detection."""

import argparse
from pathlib import Path

import numpy as np
import pandas as pd


def generate_synthetic_dataset(
    num_samples: int = 2000, random_state: int = 42
) -> pd.DataFrame:
    """Generate labeled network flow telemetry representing Benign traffic and 5 attack classes."""
    np.random.seed(random_state)

    attack_types = [
        "Benign",
        "Port Scan",
        "Brute Force",
        "DDoS",
        "Malware C2",
        "Data Exfiltration",
    ]
    probabilities = [0.55, 0.12, 0.10, 0.12, 0.06, 0.05]

    chosen_attacks = np.random.choice(attack_types, size=num_samples, p=probabilities)

    data = []
    for attack in chosen_attacks:
        if attack == "Benign":
            packets = np.random.randint(1, 100)
            bytes_count = packets * np.random.randint(64, 1500)
            duration_ms = np.random.uniform(10.0, 5000.0)
            dest_port = np.random.choice(
                [80, 443, 53, 22, 8080, np.random.randint(1024, 65535)]
            )
            protocol = np.random.choice(["TCP", "UDP"], p=[0.85, 0.15])
            failed_ratio = np.random.beta(0.5, 20.0)  # Low failed connections
            request_freq = np.random.uniform(0.1, 5.0)
            direction = np.random.choice(
                ["INBOUND", "OUTBOUND", "INTERNAL"], p=[0.4, 0.4, 0.2]
            )

        elif attack == "Port Scan":
            packets = np.random.randint(1, 4)
            bytes_count = packets * 40
            duration_ms = np.random.uniform(1.0, 50.0)
            dest_port = np.random.randint(1, 65535)
            protocol = "TCP"
            failed_ratio = np.random.uniform(0.7, 1.0)  # High RST/failed ratio
            request_freq = np.random.uniform(20.0, 100.0)
            direction = "INBOUND"

        elif attack == "Brute Force":
            packets = np.random.randint(10, 200)
            bytes_count = packets * np.random.randint(80, 250)
            duration_ms = np.random.uniform(500.0, 20000.0)
            dest_port = np.random.choice([22, 3389, 21, 80, 443])
            protocol = "TCP"
            failed_ratio = np.random.uniform(0.8, 0.99)  # High authentication failure
            request_freq = np.random.uniform(15.0, 60.0)
            direction = "INBOUND"

        elif attack == "DDoS":
            packets = np.random.randint(500, 50000)
            bytes_count = packets * np.random.randint(64, 1400)
            duration_ms = np.random.uniform(100.0, 10000.0)
            dest_port = np.random.choice([80, 443, 53, 123])
            protocol = np.random.choice(["TCP", "UDP"], p=[0.5, 0.5])
            failed_ratio = np.random.uniform(0.4, 0.9)
            request_freq = np.random.uniform(100.0, 2000.0)
            direction = "INBOUND"

        elif attack == "Malware C2":
            packets = np.random.randint(2, 30)
            bytes_count = packets * np.random.randint(100, 300)
            duration_ms = np.random.uniform(5000.0, 60000.0)
            dest_port = np.random.choice(
                [443, 8443, 4444, 9001, np.random.randint(49152, 65535)]
            )
            protocol = "TCP"
            failed_ratio = 0.05
            request_freq = np.random.uniform(0.05, 0.5)  # Periodic beaconing
            direction = "OUTBOUND"

        elif attack == "Data Exfiltration":
            packets = np.random.randint(1000, 100000)
            bytes_count = packets * 1400  # Very large outbound payloads
            duration_ms = np.random.uniform(5000.0, 300000.0)
            dest_port = np.random.choice([443, 80, 22, 21])
            protocol = "TCP"
            failed_ratio = 0.01
            request_freq = np.random.uniform(5.0, 50.0)
            direction = "OUTBOUND"

        data.append(
            {
                "source_ip": f"192.168.1.{np.random.randint(2, 254)}"
                if direction != "INBOUND"
                else f"203.0.113.{np.random.randint(1, 254)}",
                "destination_ip": f"10.0.0.{np.random.randint(2, 254)}",
                "source_port": np.random.randint(1024, 65535),
                "destination_port": int(dest_port),
                "protocol": protocol,
                "packets": int(packets),
                "bytes": int(bytes_count),
                "duration_ms": round(float(duration_ms), 2),
                "direction": direction,
                "failed_connection_ratio": round(float(failed_ratio), 4),
                "request_frequency": round(float(request_freq), 4),
                "label": attack,
            }
        )

    return pd.DataFrame(data)


def main():
    parser = argparse.ArgumentParser(description="Prepare dataset for ML training")
    parser.add_argument(
        "--samples", type=int, default=3000, help="Number of records to generate"
    )
    parser.add_argument("--output", type=str, default=None, help="Output CSV path")
    args = parser.parse_args()

    ml_dir = Path(__file__).resolve().parents[1]
    out_path = (
        Path(args.output)
        if args.output
        else (ml_dir / "datasets" / "processed" / "network_flows.csv")
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)

    df = generate_synthetic_dataset(num_samples=args.samples)
    df.to_csv(out_path, index=False)
    print(f"Dataset successfully created: {out_path} ({len(df)} records)")


if __name__ == "__main__":
    main()
