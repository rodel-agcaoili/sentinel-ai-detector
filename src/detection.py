# ML Model
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report, confusion_matrix

def run_anomaly_detection(file_path='data/synthetic_vpc_logs.csv'):
    df = pd.read_csv(file_path)
    
    # Feature Selection (Drop non-numeric IDs and the 'label' for training)
    features = ['srcport', 'dstport', 'protocol', 'packets', 'bytes']
    X = df[features]
    
    # Initialize Isolation Forest
    # n_estimators: Number of trees. 100 is standard.
    # contamination: % of data expected to be anomalies (set in the generator).
    model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
    
    # Fit and Predict
    # Returns 1 for normal, -1 for anomaly
    df['prediction'] = model.fit_predict(X)
    
    # Convert -1/1 to our 0/1 format for evaluation
    df['is_anomaly_pred'] = df['prediction'].apply(lambda x: 1 if x == -1 else 0)
    
    # Evaluate Performance (Using the labels from generator)
    print("--- Isolation Forest Performance ---")
    print(classification_report(df['label'], df['is_anomaly_pred']))
    
    # Show some flagged threats
    flagged = df[df['is_anomaly_pred'] == 1].head(5)
    print("\n--- Top Flagged Anomalies ---")
    print(flagged[['srcaddr', 'dstport', 'bytes', 'action']])

    return flagged

if __name__ == "__main__":
    run_anomaly_detection()