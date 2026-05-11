import pandas as pd

df = pd.read_csv("results/tls_metadata.csv")

df.columns = [
    "time",
    "src_ip",
    "dst_ip",
    "tls_version",
    "cipher",
    "domain"
]

df["domain"] = df["domain"].fillna("unknown")

# FEATURES
df["domain_len"] = df["domain"].apply(len)

domain_counts = df["domain"].value_counts()
df["domain_freq"] = df["domain"].map(domain_counts)

cipher_counts = df["cipher"].value_counts()
df["cipher_freq"] = df["cipher"].map(cipher_counts)

src_counts = df["src_ip"].value_counts()
df["src_freq"] = df["src_ip"].map(src_counts)

# RULES
df["anomaly"] = 0
df["reason"] = ""

mask = df["domain_len"] > 40
df.loc[mask, "anomaly"] = 1
df.loc[mask, "reason"] += "Long Domain; "

mask = df["domain_freq"] < 2
df.loc[mask, "anomaly"] = 1
df.loc[mask, "reason"] += "Rare Domain; "

mask = df["cipher_freq"] < 2
df.loc[mask, "anomaly"] = 1
df.loc[mask, "reason"] += "Rare Cipher; "

mask = df["src_freq"] > 30
df.loc[mask, "anomaly"] = 1
df.loc[mask, "reason"] += "High Connection Frequency; "

# OUTPUT
suspicious = df[df["anomaly"] == 1]

print("\nSuspicious TLS Sessions:\n")
print(suspicious[["src_ip", "dst_ip", "domain", "reason"]])

suspicious.to_csv("results/suspicious_sessions.csv", index=False)

print("\nSaved to results/suspicious_sessions.csv")
