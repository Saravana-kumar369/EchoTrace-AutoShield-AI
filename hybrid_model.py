
import numpy as np
import pandas as pd
import tensorflow as tf
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib
import os

attack_map = {0:"Normal",1:"DoS",2:"Probe",3:"R2L",4:"U2R"}
reverse_map = {v:k for k,v in attack_map.items()}

# Action mapping: 0=PASS, 1=ALERT, 2=BLOCK
action_map = {0: "PASS", 1: "ALERT", 2: "BLOCK"}

# Will be set after loading data (dynamic based on dataset)
NUM_FEATURES = None


def load_data(path):
    df = pd.read_csv(path)
    X = df.drop("label", axis=1).values.astype(np.float32)
    y = df["label"].values.astype(int)
    return X, y


def generate_action_training_data(rf, lstm, scaler, X, y):
    """
    Generate training data for the Action Decision Network.
    Uses model predictions on real data to create (input, action) pairs.
    """
    X_scaled = scaler.transform(X)
    
    action_features = []
    action_labels = []
    
    # Create per-class sequences for LSTM
    class_sequences = {}
    seq_length = 5
    for label in range(5):
        mask = (y == label)
        class_data = X_scaled[mask]
        seqs = []
        for i in range(len(class_data) - seq_length):
            seqs.append(class_data[i:i+seq_length])
        class_sequences[label] = seqs
    
    # Sample up to 200 per class to keep training tractable
    for label in range(5):
        seqs = class_sequences[label]
        if len(seqs) == 0:
            continue
        class_data_scaled = X_scaled[y == label]
        n_samples = min(200, len(seqs), len(class_data_scaled))
        
        for i in range(n_samples):
            sample = class_data_scaled[i]
            sequence = seqs[i % len(seqs)]
            
            rf_p = rf.predict_proba(sample.reshape(1, -1))[0]
            lstm_p = lstm.predict(np.expand_dims(sequence, 0), verbose=0)[0]
            combined = 0.6 * rf_p + 0.4 * lstm_p
            
            predicted_class = int(np.argmax(combined))
            confidence = float(np.max(combined))
            predicted_label = attack_map[predicted_class]
            
            # Feature vector: [rf_probs(5) + lstm_probs(5) + combined(5) + class(1) + conf(1)] = 17
            feat = np.concatenate([rf_p, lstm_p, combined, [predicted_class, confidence]])
            action_features.append(feat)
            
            # Ground truth action (threat-aware)
            if predicted_label == "Normal":
                action = 0  # PASS
            elif predicted_label in ["DoS", "R2L", "U2R"]:
                if confidence >= 0.7:
                    action = 2  # BLOCK
                elif confidence >= 0.4:
                    action = 1  # ALERT
                else:
                    action = 0  # PASS
            elif predicted_label == "Probe":
                if confidence >= 0.85:
                    action = 2  # BLOCK
                elif confidence >= 0.4:
                    action = 1  # ALERT
                else:
                    action = 0
            else:
                action = 1
            
            action_labels.append(action)
    
    return np.array(action_features), np.array(action_labels)


def train_models(path, epochs=15):
    global NUM_FEATURES
    
    X, y = load_data(path)
    NUM_FEATURES = X.shape[1]
    
    print(f"\nDataset: {len(X)} samples, {NUM_FEATURES} features")
    print(f"Classes: {dict(zip(*np.unique(y, return_counts=True)))}")
    
    # Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    # Scaler
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # ======== MODEL 1: Random Forest ========
    rf = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        min_samples_split=5,
        random_state=42,
        n_jobs=-1,
        class_weight='balanced'  # Handle class imbalance (R2L/U2R are rare)
    )
    rf.fit(X_train_scaled, y_train)
    
    rf_test_acc = rf.score(X_test_scaled, y_test)
    print(f"\n[Model 1: Random Forest]")
    print(f"  Train Accuracy: {rf.score(X_train_scaled, y_train):.4f}")
    print(f"  Test  Accuracy: {rf_test_acc:.4f}")
    
    rf_preds = rf.predict(X_test_scaled)
    print(classification_report(y_test, rf_preds,
          target_names=[attack_map[i] for i in range(5)], digits=3))
    
    # ======== MODEL 2: LSTM ========
    X_all_scaled = scaler.transform(X)
    seq_length = 5
    
    all_seq_X, all_seq_y = [], []
    for label in range(5):
        class_data = X_all_scaled[y == label]
        # Limit sequences per class (balance + speed)
        max_seqs = min(len(class_data) - seq_length, 3000)
        for i in range(max(0, max_seqs)):
            all_seq_X.append(class_data[i:i+seq_length])
            all_seq_y.append(label)
    
    Xs = np.array(all_seq_X)
    ys = np.array(all_seq_y)
    
    indices = np.random.permutation(len(Xs))
    Xs, ys = Xs[indices], ys[indices]
    
    Xs_train, Xs_test, ys_train, ys_test = train_test_split(
        Xs, ys, test_size=0.2, random_state=42, stratify=ys
    )
    
    lstm = tf.keras.Sequential([
        tf.keras.layers.LSTM(64, input_shape=(seq_length, NUM_FEATURES), return_sequences=True),
        tf.keras.layers.Dropout(0.3),
        tf.keras.layers.LSTM(32),
        tf.keras.layers.Dropout(0.2),
        tf.keras.layers.Dense(16, activation='relu'),
        tf.keras.layers.Dense(5, activation='softmax')
    ])
    lstm.compile(
        optimizer=tf.keras.optimizers.Adam(learning_rate=0.001),
        loss='sparse_categorical_crossentropy',
        metrics=['accuracy']
    )
    
    print(f"\n[Model 2: LSTM]")
    print(f"  Training on {len(Xs_train)} sequences ({NUM_FEATURES} features each)...")
    lstm.fit(Xs_train, ys_train, validation_data=(Xs_test, ys_test),
             epochs=epochs, batch_size=64, verbose=1)
    
    lstm_test_acc = lstm.evaluate(Xs_test, ys_test, verbose=0)[1]
    print(f"  LSTM Test Accuracy: {lstm_test_acc:.4f}")
    
    lstm_preds = np.argmax(lstm.predict(Xs_test, verbose=0), axis=1)
    print(classification_report(ys_test, lstm_preds,
          target_names=[attack_map[i] for i in range(5)], digits=3))
    
    # ======== MODEL 3: Action Decision Network ========
    print(f"\n[Model 3: Action Decision Network]")
    print(f"  Generating action training data...")
    
    action_X, action_y = generate_action_training_data(rf, lstm, scaler, X, y)
    
    print(f"  Samples: {len(action_X)}")
    print(f"  Actions: PASS={np.sum(action_y==0)}, ALERT={np.sum(action_y==1)}, BLOCK={np.sum(action_y==2)}")
    
    act_X_train, act_X_test, act_y_train, act_y_test = train_test_split(
        action_X, action_y, test_size=0.2, random_state=42
    )
    
    action_model = tf.keras.Sequential([
        tf.keras.layers.Dense(32, activation='relu', input_shape=(17,)),
        tf.keras.layers.Dropout(0.2),
        tf.keras.layers.Dense(16, activation='relu'),
        tf.keras.layers.Dense(3, activation='softmax')
    ])
    action_model.compile(
        optimizer=tf.keras.optimizers.Adam(learning_rate=0.001),
        loss='sparse_categorical_crossentropy',
        metrics=['accuracy']
    )
    
    action_model.fit(act_X_train, act_y_train,
                     validation_data=(act_X_test, act_y_test),
                     epochs=epochs, batch_size=32, verbose=1)
    
    act_test_acc = action_model.evaluate(act_X_test, act_y_test, verbose=0)[1]
    print(f"  Action Network Test Accuracy: {act_test_acc:.4f}")
    
    return rf, lstm, scaler, action_model


def save_models(rf, lstm, scaler, action_model=None, model_dir="models"):
    os.makedirs(model_dir, exist_ok=True)
    joblib.dump(rf, os.path.join(model_dir, "rf_model.pkl"))
    joblib.dump(scaler, os.path.join(model_dir, "scaler.pkl"))
    lstm.save(os.path.join(model_dir, "lstm_model.keras"))
    if action_model is not None:
        action_model.save(os.path.join(model_dir, "action_model.keras"))
    print(f"\nAll models saved to '{model_dir}/'")


def load_saved(model_dir="models"):
    global NUM_FEATURES
    if not os.path.exists(model_dir):
        raise FileNotFoundError(f"'{model_dir}' not found. Train first.")
    
    rf = joblib.load(os.path.join(model_dir, "rf_model.pkl"))
    scaler = joblib.load(os.path.join(model_dir, "scaler.pkl"))
    lstm = tf.keras.models.load_model(os.path.join(model_dir, "lstm_model.keras"))
    
    # Detect feature count from scaler
    NUM_FEATURES = scaler.n_features_in_
    
    action_model = None
    action_path = os.path.join(model_dir, "action_model.keras")
    if os.path.exists(action_path):
        action_model = tf.keras.models.load_model(action_path)
    
    return rf, lstm, scaler, action_model


def hybrid_predict(rf, lstm, scaler, sample, sequence, action_model=None):
    """
    Full AI pipeline:
      1. RF + LSTM classify the attack type
      2. Action Decision Network decides PASS/ALERT/BLOCK
    
    Returns: (label, confidence, action, action_conf, rf_probs, lstm_probs, action_probs)
    """
    sample_scaled = scaler.transform([sample])
    rf_p = rf.predict_proba(sample_scaled)[0]
    
    seq_scaled = scaler.transform(sequence)
    seq_input = np.expand_dims(seq_scaled, 0)
    lstm_p = lstm.predict(seq_input, verbose=0)[0]
    
    combined_probs = 0.6 * rf_p + 0.4 * lstm_p
    predicted_class = int(np.argmax(combined_probs))
    confidence = float(np.max(combined_probs))
    label = attack_map[predicted_class]
    
    if action_model is not None:
        action_input = np.concatenate([rf_p, lstm_p, combined_probs, [predicted_class, confidence]])
        action_probs = action_model.predict(action_input.reshape(1, -1), verbose=0)[0]
        action_idx = int(np.argmax(action_probs))
        action = action_map[action_idx]
        action_conf = float(np.max(action_probs))
    else:
        action_probs = np.array([0.0, 0.0, 0.0])
        if label == "Normal":
            action, action_conf = "PASS", confidence
        elif confidence >= 0.8:
            action, action_conf = "BLOCK", confidence
        else:
            action, action_conf = "ALERT", confidence
    
    return label, confidence, action, action_conf, rf_p.tolist(), lstm_p.tolist(), action_probs.tolist()


# --- Attack Traffic Generators (NSL-KDD based) ---
# These use feature statistics learned from the REAL NSL-KDD dataset

def _load_feature_stats():
    """Load feature statistics from the dataset for realistic traffic generation."""
    stats_path = os.path.join("data", "feature_stats.npz")
    if os.path.exists(stats_path):
        data = np.load(stats_path, allow_pickle=True)
        result = {}
        for k in data.files:
            arr = data[k]  # shape (2, num_features): [mean, std]
            result[int(k)] = {'mean': arr[0], 'std': arr[1]}
        return result
    return None


def _compute_and_save_feature_stats():
    """Compute per-class feature means and stds from the dataset."""
    try:
        df = pd.read_csv("data/sample_data.csv")
        X = df.drop("label", axis=1).values.astype(np.float32)
        y = df["label"].values.astype(int)
        
        stats = {}
        for label in range(5):
            mask = (y == label)
            if mask.sum() > 0:
                class_data = X[mask]
                stats[label] = {
                    'mean': class_data.mean(axis=0),
                    'std': class_data.std(axis=0) + 1e-6
                }
        
        save_dict = {}
        for label, s in stats.items():
            save_dict[f"{label}"] = np.array([s['mean'], s['std']])
        np.savez("data/feature_stats.npz", **save_dict)
        return stats
    except Exception as e:
        print(f"Warning: Could not compute feature stats: {e}")
        return None

_feature_stats_cache = None

def generate_attack_traffic(attack_type, num_samples=6):
    """
    Generate realistic traffic features based on NSL-KDD statistical distributions.
    Uses per-class mean/std from the actual dataset.
    """
    global _feature_stats_cache, NUM_FEATURES
    
    label_idx = reverse_map.get(attack_type, 0)
    
    if _feature_stats_cache is None:
        _feature_stats_cache = _load_feature_stats()
        if _feature_stats_cache is None:
            _feature_stats_cache = _compute_and_save_feature_stats()
    
    if _feature_stats_cache is not None and label_idx in _feature_stats_cache:
        mean = _feature_stats_cache[label_idx]['mean']
        std = _feature_stats_cache[label_idx]['std']
        n_feat = len(mean)
        
        features = np.random.normal(mean, std * 0.5, (num_samples, n_feat)).astype(np.float32)
        features = np.clip(features, 0, None)
    else:
        n_feat = NUM_FEATURES or 122
        features = np.random.normal(0, 0.1, (num_samples, n_feat)).astype(np.float32)
    
    sample = features[-1]
    sequence = features[:5]
    if len(features) < 5:
        while len(sequence) < 5:
            sequence = np.vstack([sequence, features[-1:]])
    
    return sample, sequence
