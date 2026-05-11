import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix

df = pd.read_csv("evaluation/detection_results.csv")

y_true = df["label"]
y_pred = df["predicted_label"]

print("\n===== Classification Report =====\n")
print(classification_report(y_true, y_pred))

print("\n===== Confusion Matrix =====\n")
print(confusion_matrix(y_true, y_pred))

