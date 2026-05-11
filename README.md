# Encrypted Data Exfiltration Detection using TLS Metadata and Machine Learning

## Overview

This project detects suspicious encrypted network traffic and potential data exfiltration attempts without decrypting TLS payloads.
The system analyzes TLS metadata, traffic behavior, timing patterns, and statistical features using unsupervised machine learning techniques.

The project combines:

* Isolation Forest
* Local Outlier Factor (LOF)
* Risk-based scoring
* Explainable alert generation

to identify anomalous encrypted traffic flows.

---

## Problem Statement

Traditional security systems struggle to inspect encrypted traffic due to TLS encryption.
Attackers exploit encrypted channels to perform:

* Data exfiltration
* Malware communication
* Beaconing
* Command and control (C2)

This project aims to detect suspicious encrypted traffic behavior without decrypting packet payloads.

---

## Key Features

* TLS metadata analysis without decryption
* Flow-based traffic modeling using 60-second windows
* Statistical, behavioral, and timing feature extraction
* Entropy-based suspicious domain detection
* Per-host baseline deviation analysis
* Hybrid anomaly detection using Isolation Forest and LOF
* Adaptive thresholding using percentiles
* Risk scoring engine
* Explainable alerts
* Visualization and analysis graphs

---

## Technologies Used

### Programming Language

* Python

### Libraries

* Pandas
* NumPy
* Scikit-learn
* Matplotlib

### Tools

* Wireshark
* Tshark
* VS Code

---

## Project Workflow

1. Capture TLS traffic using Tshark
2. Extract TLS metadata fields
3. Create traffic flows using time-window aggregation
4. Perform feature engineering
5. Normalize features
6. Detect anomalies using Isolation Forest and LOF
7. Apply adaptive threshold-based risk scoring
8. Generate explainable alerts
9. Visualize suspicious traffic behavior

---

## Dataset

The dataset was generated from real TLS network traffic captures.

### Extracted Fields

* Source IP
* Destination IP
* Packet Size
* Timestamp
* Domain (SNI)
* TLS Version
* Cipher Suite

### Synthetic Attack Injection

Optional synthetic exfiltration traffic was injected for evaluation purposes.

---

## Flow Construction

Each flow is defined as:

```text
src_ip + dst_ip + domain + time_window
```

Window size:

```text
60 seconds
```

This helps:

* reduce packet-level noise
* capture behavioral patterns
* detect automated communication
* identify exfiltration behavior




---

# Traffic Collection and TLS Metadata Extraction

## Traffic Collection

Network traffic was captured using Wireshark/Tshark from real encrypted TLS sessions generated through:

* Web browsing
* File downloads
* Cloud applications
* Streaming services
* Background system traffic

The captured packets were stored in `.pcapng` format.

Example capture command:

```bash
tshark -i Wi-Fi -w capture.pcapng
```

---

## TLS Metadata Extraction

TLS-related metadata fields were extracted from packet captures using Tshark.

### Extracted Fields

* Source IP
* Destination IP
* Packet timestamp
* Packet length
* TLS Server Name Indication (SNI)
* TLS version
* Cipher suite

### Tshark Extraction Command

```bash
tshark -r capture.pcapng ^
-T fields ^
-e ip.src ^
-e ip.dst ^
-e frame.len ^
-e frame.time_epoch ^
-e tls.handshake.extensions_server_name ^
-e tls.record.version ^
-e tls.handshake.ciphersuite ^
-E header=y ^
-E separator=\t > results/flow_raw.csv
```

---

## Why TLS Metadata?

Since TLS encrypts payload contents, this project focuses on metadata-based behavioral analysis instead of payload inspection.

Metadata such as:

* timing patterns
* packet sizes
* entropy
* beaconing behavior
* transfer rates

can still reveal suspicious encrypted communication patterns.

---


## Feature Engineering

### Statistical Features

* packet_count
* total_bytes
* avg_packet_size
* std_packet_size

### Time-Based Features

* duration
* avg_inter_arrival

### Behavioral Features

* bytes_per_sec
* packets_per_sec
* burst_ratio
* beaconing

### TLS Features

* domain_entropy
* domain_len
* cipher_diversity
* suspicious_tld

### Per-Host Baseline Features

* bytes_dev
* packets_dev

---

## Machine Learning Models

### Isolation Forest

Detects anomalies using random partitioning.

### Local Outlier Factor (LOF)

Detects anomalies using local density comparison.

### Final Decision Logic

A flow is classified as suspicious when:

* anomaly detection flags it
* risk score exceeds threshold

---

## Risk Scoring

Risk score is calculated using:

* high entropy
* abnormal transfer rate
* burst traffic
* beaconing behavior
* suspicious domains
* host deviation

Adaptive thresholds are generated using the 95th percentile of feature distributions.

---

## Final Configuration

| Parameter      | Value  |
| -------------- | ------ |
| n_estimators   | 200    |
| n_neighbors    | 20     |
| contamination  | 0.05   |
| Risk Threshold | 5      |
| Quantile       | 0.95   |
| Window Size    | 60 sec |

---

## Output Files

### CSV Outputs

* alerts.csv
* all_features.csv

### Visualization Outputs

* behavior_iso.png
* high_confidence.png
* risk.png
* model_comparison.png
* risk_heatmap.png

---

## Results

The system successfully detected suspicious encrypted traffic behavior using only TLS metadata and traffic patterns.

### Key Observations

* High entropy domains correlated with suspicious flows
* Hybrid Isolation Forest + LOF consensus improved anomaly confidence
* Risk scoring reduced false positives
* Behavioral analysis improved anomaly detection quality

---

## Limitations

* No payload inspection
* False positives possible
* Limited labeled attack data
* Synthetic attacks used for evaluation

---

## Future Improvements

* Real-time deployment
* Deep learning models
* Autoencoders
* XGBoost / Random Forest
* Larger datasets
* Live dashboard integration

---

## How to Run

### Install Requirements

```bash
pip install -r requirements.txt
```

### Run Detection Script

```bash
python scripts/detect_anomaly_ml.py
```

---

## Repository Structure

```text
encrypted-data-exfiltration-detection/
│
├── app.py
├── requirements.txt
├── README.md
├── scripts/
├── results/
├── pcaps/
├── static/
└── templates/
```

---

## Author

 
**Sushanth Balasekaran**

GitHub: [https://github.com/Sushanth1425](https://github.com/Sushanth1425)


---
