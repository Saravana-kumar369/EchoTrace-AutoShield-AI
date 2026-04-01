import argparse
import numpy as np
from hybrid_model import train_models, hybrid_predict, load_saved, save_models, generate_attack_traffic, attack_map, action_map

def demo():
    rf, lstm, scaler, action_model = load_saved()
    print("Models loaded successfully.")
    if action_model:
        print("Action Decision Network: LOADED\n")
    else:
        print("Action Decision Network: NOT FOUND (using fallback)\n")
    
    print("=" * 70)
    print("  Full AI Pipeline Test: Traffic -> RF+LSTM -> Action Network")
    print("=" * 70)
    
    attack_types = ["Normal", "DoS", "Probe", "R2L", "U2R"]
    correct = 0
    total = len(attack_types)
    
    for attack in attack_types:
        sample, sequence = generate_attack_traffic(attack)
        label, confidence, action, action_conf, rf_probs, lstm_probs, action_probs = hybrid_predict(
            rf, lstm, scaler, sample, sequence, action_model
        )
        
        match = "OK" if label == attack else "MISS"
        if label == attack:
            correct += 1
        
        print(f"\n[{match}] Simulated: {attack:8s} -> AI Detected: {label:8s} ({confidence:.2%} conf)")
        print(f"    RF:     {' | '.join(f'{attack_map[i]}: {rf_probs[i]:.3f}' for i in range(5))}")
        print(f"    LSTM:   {' | '.join(f'{attack_map[i]}: {lstm_probs[i]:.3f}' for i in range(5))}")
        print(f"    Action: PASS={action_probs[0]:.3f} | ALERT={action_probs[1]:.3f} | BLOCK={action_probs[2]:.3f}")
        print(f"    >> AI Decision: {action} ({action_conf:.2%} confidence)")
    
    print(f"\n{'=' * 70}")
    print(f"  Detection Accuracy: {correct}/{total} ({correct/total:.0%})")
    print(f"{'=' * 70}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="EchoTrace-AutoShield CLI")
    parser.add_argument("--train", action="store_true", help="Train all 3 models")
    parser.add_argument("--predict", action="store_true", help="Run demo predictions")
    args = parser.parse_args()
    if args.train:
        rf, lstm, scaler, action_model = train_models("data/sample_data.csv", epochs=15)
        save_models(rf, lstm, scaler, action_model)
    elif args.predict:
        demo()
    else:
        parser.print_help()
