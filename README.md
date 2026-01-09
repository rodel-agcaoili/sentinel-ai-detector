# sentinel-ai-detector
AI-driven network threat detection and log summarization pipeline using AWS and LLMs.

# SentinelAI: Cloud-Native Threat Detection

## Overview
This project demonstrates an end-to-end security pipeline that ingests high-bandwidth AWS VPC Flow Logs, identifies anomalies using Unsupervised Learning, and provides human-readable threat summaries using LLMs.

## Architecture
1. **Ingestion:** Boto3 fetches logs from AWS CloudWatch/S3.
2. **Analysis:** Scikit-Learn (Isolation Forest) flags outliers in network traffic (e.g., unusual byte transfers).
3. **Reasoning:** Amazon Bedrock (Claude 3) or Llama 3 summarizes the flagged log for a SOC analyst.

## Tech Stack
- **Cloud:** AWS (S3, Lambda, SageMaker)
- **AI/ML:** Python, Scikit-Learn, PyTorch
- **Security:** VPC Flow Log Analysis