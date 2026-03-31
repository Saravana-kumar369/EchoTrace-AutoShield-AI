import argparse
import numpy as np
from hybrid_model import train_models, hybrid_predict, load_saved, save_models

def preventive_action(label, confidence, threshold=0.8):
    if label != "Normal" and confidence >= threshold:
        print(f"BLOCK: {label} ({confidence:.2f})")
    elif label != "Normal":
        print(f"ALERT: low-confidence {label} ({confidence:.2f})")
    else:
        print("PASS: Normal")

def demo():
    rf, lstm, scaler = load_saved()
    sample = np.array([0.2,0.5,1.2,0.7])
    sequence = np.array([[0.1,0.4,1.0,0.6], [0.2,0.5,1.1,0.7], [0.3,0.6,1.2,0.8], [0.2,0.5,1.3,0.9], [0.1,0.4,1.2,0.7]])
    label, confidence = hybrid_predict(rf, lstm, scaler, sample, sequence)
    print("Prediction:", label, "Confidence:", confidence)
    preventive_action(label, confidence)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--train", action="store_true")
    parser.add_argument("--predict", action="store_true")
    args = parser.parse_args()
    if args.train:
        rf, lstm, scaler = train_models("data/sample_data.csv", epochs=15)
        save_models(rf, lstm, scaler)
    elif args.predict:
        demo()
    else:
        parser.print_help()
# import numpy as np
# from hybrid_model import train_models, hybrid_predict

# rf, lstm, scaler = train_models("data/sample_data.csv")

# sample = [0.2,0.5,1.2,0.7]
# sequence = [
#     [0.1,0.4,1.0,0.6],
#     [0.2,0.5,1.1,0.7],
#     [0.3,0.6,1.2,0.8],
#     [0.2,0.5,1.3,0.9],
#     [0.1,0.4,1.2,0.7]
# ]

# result, conf = hybrid_predict(rf, lstm, scaler, sample, sequence)
# print("Prediction:", result)
# print("Confidence:", conf)
# input("Press Enter to exit...")
