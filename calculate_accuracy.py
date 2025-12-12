import pandas as pd
import os
from sklearn.metrics import accuracy_score, precision_score, recall_score, confusion_matrix

def calculate_accuracy(file_path="data/processed/simulation_results.csv"):
    if not os.path.exists(file_path):
        print(f"Error: Results file not found at {file_path}")
        return

    try:
        data = pd.read_csv(file_path)
        if data.empty:
            print("Results file is empty.")
            return

        # Ensure correct types
        y_true = data['is_attacker']
        y_pred = data['predicted_anomaly']

        # Calculate metrics
        acc = accuracy_score(y_true, y_pred)
        prec = precision_score(y_true, y_pred, zero_division=0)
        rec = recall_score(y_true, y_pred, zero_division=0)
        cm = confusion_matrix(y_true, y_pred)

        print("\n--- Model Performance Metrics ---")
        print(f"Total Samples: {len(data)}")
        print(f"Accuracy:      {acc:.2%}")
        print(f"Precision:     {prec:.2%}")
        print(f"Recall:        {rec:.2%}")
        print("\nConfusion Matrix:")
        print(cm)
        print("(TN, FP)")
        print("(FN, TP)")
        print("---------------------------------")

    except Exception as e:
        print(f"Error calculating metrics: {e}")

if __name__ == "__main__":
    calculate_accuracy()
