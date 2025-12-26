# FERAOS
📖 Overview
FeAROS is an AI-Assisted Security Information and Event Management (SIEM) system designed to enhance conventional security monitoring capabilities. While traditional SIEMs rely on predefined rules and static thresholds—often failing against unknown attacks and subtle malicious behavior—FeAROS utilizes machine learning-based behavioral analysis to detect anomalies in real-time.  
This project shifts SIEM from a passive monitoring tool into an active cyber defense platform by implementing a complete Detect → Decide → Act loop.  
🚀 Key Features
ML-Driven Anomaly Detection: Utilizes Isolation Forest to identify abnormal behavior without requiring labeled attack data.  
Automated Response (SOAR): Automatically isolates affected hosts via firewall-level enforcement when risk thresholds are exceeded.  
Intelligent Enrichment: Enhances detected anomalies with context such as user trust levels and process criticality to reduce false positives.  
Unified Log Normalization: Ingests logs from servers, endpoints, and network devices, normalizing them into a common schema.  
Risk Correlation: Evaluates risk across events over a sliding time window to detect persistent threats.  
🏗️ System Architecture
The system operates through a seven-layer pipeline designed to function independently yet integrate seamlessly.  
1. Data Ingestion & Normalization
Ingestion: Logs are collected using Filebeat and stored in Elasticsearch.  
Normalization: Raw logs are parsed into a uniform schema (Timestamp, Host, User, Process, Message, IP) to ensure consistency across heterogeneous sources.  
2. Feature Engineering
Events are transformed into numerical representations for the ML model using:
Temporal features (e.g., hour of activity).  
Text vectorization via TF-IDF + Hashing.  
Categorical encoding (One-Hot Encoding) for users and hosts.  
Feature scaling using StandardScaler.  
3. Machine Learning Detection Engine
Model: Isolation Forest.  
Function: Learns typical activity patterns, log frequency, and normal process execution. Events deviating from this baseline are flagged as anomalies.  
4. Event Enrichment & Correlation
Context: Trusted administrative actions are risk-suppressed (not ignored), while high-risk contexts escalate the score.  
Correlation: A sliding time window aggregates risk to identify repeated suspicious behavior and correlate events across hosts.  
5. Automated Response
When a threat exceeds the defined risk threshold, the system autonomously:
Connects to the affected host via SSH.  
Applies firewall rules to isolate the system.  
Maintains administrative access for recovery purposes.  
