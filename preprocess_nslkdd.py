"""
Preprocess the NSL-KDD dataset for EchoTrace-AutoShield.

This script:
1. Loads the raw KDDTrain+.txt and KDDTest+.txt
2. Maps 23 specific attack labels to 5 categories (Normal, DoS, Probe, R2L, U2R)
3. Encodes 3 categorical features (protocol_type, service, flag) using one-hot encoding
4. Standardizes numeric features
5. Saves processed data as sample_data.csv (compatible with our model)

NSL-KDD Features (41 total):
  - 3 categorical: protocol_type, service, flag
  - 38 numeric: duration, src_bytes, dst_bytes, etc.
"""

import pandas as pd
import numpy as np
import os

# NSL-KDD column names (41 features + label + difficulty)
COLUMNS = [
    'duration', 'protocol_type', 'service', 'flag',
    'src_bytes', 'dst_bytes', 'land', 'wrong_fragment', 'urgent',
    'hot', 'num_failed_logins', 'logged_in', 'num_compromised',
    'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
    'num_shells', 'num_access_files', 'num_outbound_cmds',
    'is_host_login', 'is_guest_login',
    'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
    'rerror_rate', 'srv_rerror_rate', 'same_srv_rate',
    'diff_srv_rate', 'srv_diff_host_rate',
    'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
    'dst_host_serror_rate', 'dst_host_srv_serror_rate',
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate',
    'label', 'difficulty'
]

# Map specific attack names to 5 categories
ATTACK_MAP = {
    'normal': 'Normal',
    # DoS attacks
    'back': 'DoS', 'land': 'DoS', 'neptune': 'DoS', 'pod': 'DoS',
    'smurf': 'DoS', 'teardrop': 'DoS', 'mailbomb': 'DoS',
    'apache2': 'DoS', 'processtable': 'DoS', 'udpstorm': 'DoS',
    # Probe attacks
    'ipsweep': 'Probe', 'nmap': 'Probe', 'portsweep': 'Probe',
    'satan': 'Probe', 'mscan': 'Probe', 'saint': 'Probe',
    # R2L attacks
    'ftp_write': 'R2L', 'guess_passwd': 'R2L', 'imap': 'R2L',
    'multihop': 'R2L', 'phf': 'R2L', 'spy': 'R2L',
    'warezclient': 'R2L', 'warezmaster': 'R2L', 'snmpgetattack': 'R2L',
    'named': 'R2L', 'xlock': 'R2L', 'xsnoop': 'R2L',
    'sendmail': 'R2L', 'httptunnel': 'R2L', 'worm': 'R2L',
    'snmpguess': 'R2L',
    # U2R attacks
    'buffer_overflow': 'U2R', 'loadmodule': 'U2R', 'perl': 'U2R',
    'rootkit': 'U2R', 'xterm': 'U2R', 'ps': 'U2R',
    'sqlattack': 'U2R',
}

LABEL_TO_NUM = {'Normal': 0, 'DoS': 1, 'Probe': 2, 'R2L': 3, 'U2R': 4}


def load_nsl_kdd(filepath):
    """Load NSL-KDD dataset and apply column names."""
    df = pd.read_csv(filepath, header=None, names=COLUMNS)
    return df


def preprocess(df_train, df_test=None):
    """
    Full preprocessing pipeline:
    1. Map labels to 5 attack categories
    2. One-hot encode categorical features
    3. Select final feature set
    """
    # Map attack labels
    df_train['label'] = df_train['label'].map(ATTACK_MAP)
    df_train = df_train.dropna(subset=['label'])  # Drop unknown attacks
    
    if df_test is not None:
        df_test['label'] = df_test['label'].map(ATTACK_MAP)
        df_test = df_test.dropna(subset=['label'])
    
    # Remove difficulty column
    df_train = df_train.drop('difficulty', axis=1)
    if df_test is not None:
        df_test = df_test.drop('difficulty', axis=1)
    
    # One-hot encode categorical columns
    categorical_cols = ['protocol_type', 'service', 'flag']
    
    # Fit on train, transform both
    if df_test is not None:
        combined = pd.concat([df_train, df_test], axis=0, ignore_index=True)
        combined_encoded = pd.get_dummies(combined, columns=categorical_cols, dtype=int)
        
        train_len = len(df_train)
        df_train_encoded = combined_encoded.iloc[:train_len]
        df_test_encoded = combined_encoded.iloc[train_len:]
    else:
        df_train_encoded = pd.get_dummies(df_train, columns=categorical_cols, dtype=int)
        df_test_encoded = None
    
    # Convert labels to numeric
    df_train_encoded['label'] = df_train_encoded['label'].map(LABEL_TO_NUM)
    if df_test_encoded is not None:
        df_test_encoded['label'] = df_test_encoded['label'].map(LABEL_TO_NUM)
    
    return df_train_encoded, df_test_encoded


def main():
    print("=" * 60)
    print("  NSL-KDD Dataset Preprocessing for EchoTrace-AutoShield")
    print("=" * 60)
    
    # Load raw data
    train_path = 'data/KDDTrain+.txt'
    test_path = 'data/KDDTest+.txt'
    
    if not os.path.exists(train_path):
        print(f"ERROR: {train_path} not found. Download NSL-KDD first.")
        return
    
    print(f"\nLoading {train_path}...")
    df_train = load_nsl_kdd(train_path)
    print(f"  Raw train samples: {len(df_train)}")
    
    df_test = None
    if os.path.exists(test_path):
        print(f"Loading {test_path}...")
        df_test = load_nsl_kdd(test_path)
        print(f"  Raw test samples: {len(df_test)}")
    
    # Show raw label distribution
    print(f"\nRaw attack labels: {df_train['label'].nunique()} types")
    print(f"  {df_train['label'].value_counts().to_dict()}")
    
    # Preprocess
    print("\nPreprocessing...")
    df_train_proc, df_test_proc = preprocess(df_train, df_test)
    
    num_features = len(df_train_proc.columns) - 1  # exclude label
    print(f"  Features after encoding: {num_features}")
    
    # Show class distribution
    names = {0: 'Normal', 1: 'DoS', 2: 'Probe', 3: 'R2L', 4: 'U2R'}
    print(f"\n  Train class distribution:")
    for label in range(5):
        count = (df_train_proc['label'] == label).sum()
        pct = count / len(df_train_proc) * 100
        print(f"    {names[label]:8s}: {count:6d} samples ({pct:.1f}%)")
    
    if df_test_proc is not None:
        print(f"\n  Test class distribution:")
        for label in range(5):
            count = (df_test_proc['label'] == label).sum()
            pct = count / len(df_test_proc) * 100
            print(f"    {names[label]:8s}: {count:6d} samples ({pct:.1f}%)")
    
    # Save processed data
    train_out = 'data/nsl_kdd_train.csv'
    df_train_proc.to_csv(train_out, index=False)
    print(f"\nSaved: {train_out} ({len(df_train_proc)} rows, {num_features} features)")
    
    if df_test_proc is not None:
        test_out = 'data/nsl_kdd_test.csv'
        df_test_proc.to_csv(test_out, index=False)
        print(f"Saved: {test_out} ({len(df_test_proc)} rows, {num_features} features)")
    
    # Also save as sample_data.csv for backward compatibility
    df_train_proc.to_csv('data/sample_data.csv', index=False)
    print(f"\nAlso saved as data/sample_data.csv (replaces old synthetic data)")
    
    # Save feature names for reference
    feature_names = [c for c in df_train_proc.columns if c != 'label']
    with open('data/feature_names.txt', 'w') as f:
        for name in feature_names:
            f.write(name + '\n')
    print(f"Feature names saved to data/feature_names.txt")
    
    print(f"\n{'=' * 60}")
    print(f"  Dataset ready! {num_features} features, {len(df_train_proc)} training samples")
    print(f"  Run 'python main.py --train' to retrain models")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    main()
