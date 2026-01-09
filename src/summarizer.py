# LLM Integration
import requests
import json

def summarize_threat(log_entry):
    """
    Sends a flagged log entry to a local Llama 3 instance for analysis.
    """
    url = "http://localhost:11434/api/generate"
    
    # Constructing a "Security Analyst" prompt
    prompt = f"""
    You are a Senior Cybersecurity Analyst. Analyze the following VPC Flow Log entry flagged as an anomaly:
    {log_entry}
    
    Provide a concise 2-3 sentence summary of the potential threat and suggest one immediate mitigation step. 
    Format: 
    - Threat Type:
    - Summary:
    - Mitigation:
    """

    data = {
        "model": "llama3",
        "prompt": prompt,
        "stream": False
    }

    try:
        response = requests.post(url, json=data)
        return response.json().get('response', "Could not generate summary.")
    except Exception as e:
        return f"Error connecting to Ollama: {e}"

# Example usage with one of the synthetic anomalies
if __name__ == "__main__":
    sample_log = "{'srcaddr': '10.0.5.12', 'dstport': 4444, 'bytes': 9500000, 'action': 'ACCEPT'}"
    print(summarize_threat(sample_log))
    