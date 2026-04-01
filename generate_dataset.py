"""
Generate a realistic synthetic network traffic dataset for EchoTrace-AutoShield.

Features (inspired by NSL-KDD / CICIDS style):
  f1 = packet_rate       (packets per second, normalized 0-1)
  f2 = byte_ratio         (bytes_sent / bytes_received, normalized 0-1)
  f3 = connection_duration (duration of connection, normalized 0-1)
  f4 = flag_anomaly_score  (unusual TCP flags / protocol anomalies, 0-1)

Labels:
  0 = Normal   — low packet rate, balanced byte ratio, moderate duration, low anomaly
  1 = DoS      — very high packet rate, high byte ratio (flooding), short duration bursts
  2 = Probe    — low packet rate, low byte ratio (scanning), varied duration, moderate anomaly
  3 = R2L      — moderate packet rate, high byte ratio, long duration (persistent connection)
  4 = U2R      — low-moderate packet rate, varied ratio, long duration, HIGH anomaly score

Each class has distinct statistical distributions so the RF + LSTM can genuinely learn
to separate them.
"""

import numpy as np
import pandas as pd
import os

np.random.seed(42)

SAMPLES_PER_CLASS = 400  # 2000 total rows
TOTAL = SAMPLES_PER_CLASS * 5

def generate_class(label, n):
    """Generate n samples for a given attack class with realistic distributions."""
    if label == 0:  # Normal
        f1 = np.random.normal(0.20, 0.08, n).clip(0.01, 0.50)   # low packet rate
        f2 = np.random.normal(0.50, 0.10, n).clip(0.20, 0.80)   # balanced byte ratio
        f3 = np.random.normal(0.50, 0.15, n).clip(0.10, 0.90)   # moderate duration
        f4 = np.random.normal(0.10, 0.05, n).clip(0.00, 0.30)   # low anomaly score
    
    elif label == 1:  # DoS — high rate, high bytes, short bursts
        f1 = np.random.normal(0.85, 0.08, n).clip(0.60, 1.00)   # very high packet rate
        f2 = np.random.normal(0.80, 0.10, n).clip(0.55, 1.00)   # high outbound bytes (flooding)
        f3 = np.random.normal(0.15, 0.08, n).clip(0.01, 0.40)   # short duration bursts
        f4 = np.random.normal(0.55, 0.15, n).clip(0.20, 0.90)   # moderate-high anomaly
    
    elif label == 2:  # Probe — low rate scanning, varied ports
        f1 = np.random.normal(0.30, 0.10, n).clip(0.05, 0.55)   # low-moderate rate
        f2 = np.random.normal(0.25, 0.10, n).clip(0.05, 0.50)   # low bytes (just scanning)
        f3 = np.random.normal(0.35, 0.15, n).clip(0.05, 0.70)   # varied duration
        f4 = np.random.normal(0.60, 0.12, n).clip(0.30, 0.90)   # high anomaly (unusual patterns)
    
    elif label == 3:  # R2L — sustained connection, data exfiltration
        f1 = np.random.normal(0.40, 0.10, n).clip(0.15, 0.65)   # moderate rate
        f2 = np.random.normal(0.75, 0.08, n).clip(0.50, 0.95)   # high byte ratio (extracting data)
        f3 = np.random.normal(0.80, 0.10, n).clip(0.55, 1.00)   # long duration
        f4 = np.random.normal(0.40, 0.12, n).clip(0.15, 0.70)   # moderate anomaly
    
    elif label == 4:  # U2R — privilege escalation, high anomaly
        f1 = np.random.normal(0.25, 0.10, n).clip(0.05, 0.50)   # low-moderate rate
        f2 = np.random.normal(0.45, 0.15, n).clip(0.10, 0.80)   # varied byte ratio
        f3 = np.random.normal(0.70, 0.12, n).clip(0.40, 0.95)   # long duration (working on target)
        f4 = np.random.normal(0.85, 0.08, n).clip(0.60, 1.00)   # VERY high anomaly (key indicator)
    
    return np.column_stack([f1, f2, f3, f4]), np.full(n, label, dtype=int)


def main():
    all_X = []
    all_y = []
    
    for label in range(5):
        X, y = generate_class(label, SAMPLES_PER_CLASS)
        all_X.append(X)
        all_y.append(y)
    
    X = np.vstack(all_X)
    y = np.concatenate(all_y)
    
    # Shuffle the data
    indices = np.random.permutation(len(X))
    X = X[indices]
    y = y[indices]
    
    # Round to 4 decimal places for readability
    X = np.round(X, 4)
    
    # Create DataFrame
    df = pd.DataFrame(X, columns=['f1', 'f2', 'f3', 'f4'])
    df['label'] = y
    
    os.makedirs('data', exist_ok=True)
    df.to_csv('data/sample_data.csv', index=False)
    
    print(f"Generated {len(df)} samples across 5 classes:")
    print(f"  Class distribution:")
    for label in range(5):
        names = {0: 'Normal', 1: 'DoS', 2: 'Probe', 3: 'R2L', 4: 'U2R'}
        count = (df['label'] == label).sum()
        subset = df[df['label'] == label][['f1','f2','f3','f4']]
        print(f"    {names[label]:8s}: {count} samples | "
              f"f1={subset['f1'].mean():.3f} f2={subset['f2'].mean():.3f} "
              f"f3={subset['f3'].mean():.3f} f4={subset['f4'].mean():.3f}")
    
    print(f"\nSaved to data/sample_data.csv")
    print(f"\nFeature meanings:")
    print(f"  f1 = packet_rate (pkts/sec normalized)")
    print(f"  f2 = byte_ratio (sent/received normalized)")
    print(f"  f3 = connection_duration (normalized)")
    print(f"  f4 = flag_anomaly_score (protocol anomalies)")


if __name__ == "__main__":
    main()
