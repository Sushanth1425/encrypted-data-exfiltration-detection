import os
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.neighbors import LocalOutlierFactor
import matplotlib.pyplot as plt


# LOAD DATA
df = pd.read_csv("results/flow_raw.csv", sep="\t")

df = df.rename(columns={
    "ip.src": "src_ip",
    "ip.dst": "dst_ip",
    "frame.len": "packet_size",
    "frame.time_epoch": "time",
    "tls.handshake.extensions_server_name": "domain",
    "tls.record.version": "tls_version",
    "tls.handshake.ciphersuite": "cipher"
})


df["domain"] = df["domain"].fillna("unknown")
df["cipher"] = df["cipher"].fillna("unknown")

df["time"] = pd.to_numeric(df["time"], errors="coerce")
df["packet_size"] = pd.to_numeric(df["packet_size"], errors="coerce")

df = df.dropna(subset=["time", "packet_size"])
df["label"] = 0

print("Dataset size:", len(df))

'''
# SYNTHETIC ATTACK INJECTION
def inject_exfiltration(data, n=30):
    rows = []
    for _ in range(n):
        rows.append({
            "src_ip": "attacker",
            "dst_ip": "malicious",
            "packet_size": np.random.randint(800, 1500),
            "time": np.random.uniform(data["time"].min(), data["time"].max()),
            "domain": "exfil-" + ''.join(np.random.choice(list("abcdef0123456789"), 50)) + ".xyz",
            "tls_version": 771,
            "cipher": "0x1301", 
            "label": 1
        })
    return pd.concat([data, pd.DataFrame(rows)], ignore_index=True)

#df = inject_exfiltration(df)
'''

# TIME WINDOWING
WINDOW = 60
df["time_bin"] = (df["time"] // WINDOW).astype(int)


# FLOW CREATION
df["flow"] = (df["src_ip"] + "-" + df["dst_ip"] + "-" + df["domain"] + "-" + df["time_bin"].astype(str))
flows = df.groupby("flow")

# FEATURE ENGINEERING
features = pd.DataFrame()

flow_labels = flows["label"].max() 
features["true_label"] = flow_labels

# Basic
features["packet_count"] = flows.size()
features["total_bytes"] = flows["packet_size"].sum()
features["avg_packet_size"] = flows["packet_size"].mean()
features["std_packet_size"] = flows["packet_size"].std().fillna(0)

# Time
features["start_time"] = flows["time"].min()
features["end_time"] = flows["time"].max()
features["duration"] = (features["end_time"] - features["start_time"]).replace(0, 0.001)

# Rates
features["bytes_per_sec"] = features["total_bytes"] / features["duration"]
features["packets_per_sec"] = features["packet_count"] / features["duration"]

# Inter-arrival
def inter_arrival(x):
    return np.mean(np.diff(sorted(x))) if len(x) > 1 else 0

features["avg_inter_arrival"] = flows["time"].apply(inter_arrival)


# TLS FEATURES (REAL)
domain_map = flows["domain"].first().fillna("unknown")
cipher_map = flows["cipher"].first().fillna("unknown")
version_map = flows["tls_version"].first().fillna(0)

features["domain_len"] = domain_map.apply(len)

def entropy(s):
    prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(list(s))]
    return -sum([p * np.log2(p) for p in prob])

features["domain_entropy"] = domain_map.apply(entropy)

features["tls_version"] = version_map
features["cipher_len"] = cipher_map.apply(len)
features["cipher_diversity"] = flows["cipher"].nunique()


# Suspicious TLD
suspicious_tlds = ["xyz", "top", "gq", "tk"]
features["suspicious_tld"] = domain_map.apply(lambda d: any(str(d).endswith(tld) for tld in suspicious_tlds)).astype(int)


# BEHAVIOR FEATURES
features["beaconing"] = features["avg_inter_arrival"].apply(lambda x: 1 if 0 < x < 1 else 0)

features["burst_ratio"] = features["packets_per_sec"] / (features["avg_inter_arrival"] + 1e-5)


# PER-HOST BASELINE
features["src_ip"] = features.index.map(lambda x: x.split("-")[0])

baseline = features.groupby("src_ip")[["bytes_per_sec", "packets_per_sec"]].mean()
baseline.columns = ["base_bytes", "base_packets"]

features = features.join(baseline, on="src_ip")

features["bytes_dev"] = features["bytes_per_sec"] / (features["base_bytes"] + 1e-5)
features["packets_dev"] = features["packets_per_sec"] / (features["base_packets"] + 1e-5)


# CLEAN
features = features.replace([np.inf, -np.inf], 0).fillna(0)

# NORMALIZATION
X = features.select_dtypes(include=np.number)

scaler = StandardScaler()
scaled = scaler.fit_transform(X)


# ANOMALY DETECTION
iso = IsolationForest(n_estimators=200, contamination=0.05, random_state=42)
features["iso_flag"] = iso.fit_predict(scaled)

lof = LocalOutlierFactor(n_neighbors=20, contamination=0.05)
features["lof_flag"] = np.where(lof.fit_predict(scaled) == -1, 1, 0)


# ADAPTIVE THRESHOLDS
q_entropy = features["domain_entropy"].quantile(0.95)
q_bytes = features["bytes_per_sec"].quantile(0.95)
q_dev = features["bytes_dev"].quantile(0.95)
q_burst = features["burst_ratio"].quantile(0.95)


# RISK SCORING
def risk(row):
    score = 0
    if row["domain_entropy"] > q_entropy:
        score += 2
    if row["bytes_per_sec"] > q_bytes:
        score += 2
    if row["bytes_dev"] > q_dev:
        score += 2
    if row["burst_ratio"] > q_burst:
        score += 1
    if row["beaconing"]:
        score += 1
    if row["suspicious_tld"]:
        score += 1
    if row["domain_len"] > 40:
        score += 1
    return score

features["risk_score"] = features.apply(risk, axis=1)

RISK_THRESHOLD = 7

features["pred"] = np.where(
    ((features["iso_flag"] == -1) | (features["lof_flag"] == 1)) &
    (features["risk_score"] >= RISK_THRESHOLD), 1, 0)

# CONFIDENCE
features["both_models"] = ((features["iso_flag"] == -1) & (features["lof_flag"] == 1))

features["confidence"] = features.apply(
    lambda r: "High" if r["both_models"] and r["risk_score"] >= 4
    else ("Medium" if r["risk_score"] >= 2 else "Low"),
    axis=1
)


# ALERTS
alerts = features[((features["iso_flag"] == -1) | (features["lof_flag"] == 1)) & (features["risk_score"] >= RISK_THRESHOLD)].copy()


# EXPLANATION ENGINE
def explain(row):
    reasons = []
    if row["domain_entropy"] > q_entropy:
        reasons.append("High Entropy")
    if row["bytes_dev"] > q_dev:
        reasons.append("Host Deviation")
    if row["burst_ratio"] > q_burst:
        reasons.append("Burst Traffic")
    if row["beaconing"]:
        reasons.append("Beaconing")
    if row["suspicious_tld"]:
        reasons.append("Suspicious TLD")
    if row["domain_len"] > 40:
        reasons.append("Long Domain")
    return ", ".join(reasons)

alerts["reason"] = alerts.apply(explain, axis=1)


# STATS
print("\nTotal flows:", len(features))
print("ISO anomalies:", (features["iso_flag"] == -1).sum())
print("LOF anomalies:", (features["lof_flag"] == 1).sum())
print("High confidence:", features["both_models"].sum())
print("Alerts generated:", len(alerts))
print("\nTop Alerts:")
print(alerts[["risk_score", "confidence", "reason"]].head(10))

'''
# METRICS
TP = ((features["pred"] == 1) & (features["true_label"] == 1)).sum()
FP = ((features["pred"] == 1) & (features["true_label"] == 0)).sum()
FN = ((features["pred"] == 0) & (features["true_label"] == 1)).sum()
TN = ((features["pred"] == 0) & (features["true_label"] == 0)).sum()

detection_rate = TP / (TP + FN + 1e-5)
false_positive_rate = FP / (FP + TN + 1e-5)
precision = TP / (TP + FP + 1e-5)

print("\n METRICS ")
print("Detection Rate:", detection_rate)
print("False Positive Rate:", false_positive_rate)
print("Precision:", precision)
print("Total Alerts:", (features["pred"] == 1).sum())
print(features[["true_label", "pred"]].value_counts())

'''
# SAVE
os.makedirs("results", exist_ok=True)

features.to_csv("results/all_features.csv")
alerts.to_csv("results/alerts.csv")


# VISUALIZATIONS

# 1. Behavior space
plt.figure()
plt.scatter(features["domain_entropy"], features["bytes_per_sec"], c=(features["iso_flag"] == -1), cmap="coolwarm")
plt.xlabel("Entropy")
plt.ylabel("Bytes/sec")
plt.title("Isolation Forest Detection")
plt.savefig("results/behavior_iso.png")
plt.show()


# 2. High confidence
plt.figure()
plt.scatter(features["domain_entropy"], features["bytes_per_sec"], c=features["both_models"], cmap="coolwarm")
plt.title("High Confidence Anomalies (Both Models)")
plt.xlabel("Entropy")
plt.ylabel("Bytes/sec")
plt.savefig("results/high_confidence.png")
plt.show()


# 3. Risk distribution
plt.figure()
plt.hist(features["risk_score"], bins=20)
plt.title("Risk Score Distribution")
plt.savefig("results/risk.png")
plt.show()


# 4. Model comparison
plt.figure()
counts = [(features["iso_flag"] == -1).sum(), (features["lof_flag"] == 1).sum()]

plt.bar(["Isolation Forest", "LOF"], counts)
plt.title("Model Comparison")
plt.ylabel("Anomaly Count")
plt.savefig("results/model_comparison.png")
plt.show()

plt.figure()
plt.scatter(features["bytes_per_sec"], features["packets_per_sec"], c=features["risk_score"], cmap="hot")
plt.colorbar(label="Risk Score")
plt.xlabel("Bytes/sec")
plt.ylabel("Packets/sec")
plt.title("Risk Heatmap")
plt.savefig("results/risk_heatmap.png")
plt.show()