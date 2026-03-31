
import numpy as np
import pandas as pd
import tensorflow as tf
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import joblib
import os

attack_map = {0:"Normal",1:"DoS",2:"Probe",3:"R2L",4:"U2R"}

def load_data(path):
    df = pd.read_csv(path)
    return df.drop("label",axis=1).values, df["label"].values

def preprocess_data(X):
    scaler = StandardScaler()
    return scaler.fit_transform(X), scaler

def create_sequences(X,y,seq_length=5):
    Xs, ys = [],[]
    for i in range(len(X)-seq_length):
        Xs.append(X[i:i+seq_length])
        ys.append(y[i+seq_length])
    return np.array(Xs), np.array(ys)

def train_models(path, epochs=2):
    X,y = load_data(path)
    X,scaler = preprocess_data(X)

    rf = RandomForestClassifier().fit(X,y)

    Xs,ys = create_sequences(X,y)
    lstm = tf.keras.Sequential([
        tf.keras.layers.LSTM(32,input_shape=(Xs.shape[1],Xs.shape[2])),
        tf.keras.layers.Dense(5,activation='softmax')
    ])
    lstm.compile(optimizer='adam',loss='sparse_categorical_crossentropy')
    lstm.fit(Xs,ys,epochs=epochs,verbose=0)

    return rf,lstm,scaler

def save_models(rf, lstm, scaler, model_dir="models"):
    os.makedirs(model_dir, exist_ok=True)
    joblib.dump(rf, os.path.join(model_dir, "rf_model.pkl"))
    joblib.dump(scaler, os.path.join(model_dir, "scaler.pkl"))
    lstm.save(os.path.join(model_dir, "lstm_model.keras"))
    print(f"Models successfully saved to '{model_dir}' directory.")

def load_saved(model_dir="models"):
    if not os.path.exists(model_dir):
        raise FileNotFoundError(f"Model directory '{model_dir}' not found. Please train models first.")
    
    rf = joblib.load(os.path.join(model_dir, "rf_model.pkl"))
    scaler = joblib.load(os.path.join(model_dir, "scaler.pkl"))
    lstm = tf.keras.models.load_model(os.path.join(model_dir, "lstm_model.keras"))
    return rf, lstm, scaler

def hybrid_predict(rf,lstm,scaler,sample,sequence):
    rf_p = rf.predict_proba(scaler.transform([sample]))[0]
    seq = scaler.transform(sequence)
    seq = np.expand_dims(seq,0)
    lstm_p = lstm.predict(seq,verbose=0)[0]
    probs = 0.6*rf_p + 0.4*lstm_p
    cls = int(np.argmax(probs))
    return attack_map[cls], float(np.max(probs))
