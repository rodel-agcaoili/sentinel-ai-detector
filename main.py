from src.generate_logs import generate_vpc_flow_logs
from src.detection import run_anomaly_detection
from src.summarizer import summarize_threat
import pandas as pd

def main():
    print("Starting SentinelAI Pipeline...")
    
    # Generate synthetic VPC Flow Logs
    generate_vpc_flow_logs(num_records=1000)
    
    print("🔍 Analyzing logs for anomalies...")
    df_results = run_anomaly_detection()
    
    # Summarize the most critical anomaly
    anomalies = df_results[df_results['is_anomaly_pred'] == 1]
    
    if not anomalies.empty:
        print(f"Found {len(anomalies)} anomalies. Summarizing the most critical...")
        
        # Sort by bytes or packets to find the most "impactful" threats
        critical_threats = anomalies.sort_values(by='bytes', ascending=False).head(5)
        
        print(f"Summarizing the top {len(critical_threats)} most critical threats...\n")
        
        for index, row in critical_threats.iterrows():
            threat_data = row.to_dict()
            summary = summarize_threat(threat_data)
            print(f"--- THREAT REPORT (Source: {threat_data['srcaddr']}) ---")
            print(f"{summary}\n")
            print("-" * 40)
    else:
        print("No anomalies detected.")

if __name__ == "__main__":
    main()