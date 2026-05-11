""" import pandas as pd
import numpy as np
import os
import glob
import matplotlib.pyplot as plt

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    confusion_matrix,
    classification_report,
    roc_auc_score,
    roc_curve,
    precision_recall_curve
)

from sklearn.ensemble import RandomForestClassifier, IsolationForest


# =====
# 1. LOAD DATA (CICIDS2017)
# =====
def load_data(folder_path):
    all_files = glob.glob(folder_path + "/*.csv")

    df_list = []

    for file in all_files:
        print("Loading:", file)

        df = pd.read_csv(file, low_memory=False)
        df.columns = df.columns.str.strip()

        # find label column
        label_col = None
        for col in df.columns:
            if col.lower() == "label":
                label_col = col
                break

        if label_col is None:
            print("Skipping:", file)
            continue

        # binary label
        df["label"] = df[label_col].apply(
            lambda x: 0 if str(x).strip().upper() == "BENIGN" else 1
        )

        # DROP ORIGINAL LABEL COLUMN (IMPORTANT)
        df = df.drop(columns=[label_col])

        df_list.append(df)

    df = pd.concat(df_list, ignore_index=True)

    # drop metadata
    drop_cols = ["Flow ID", "Source IP", "Destination IP", "Timestamp"]
    df = df.drop(columns=[c for c in drop_cols if c in df.columns])

    # FORCE NUMERIC (THIS FIXES YOUR ERROR)
    df = df.apply(pd.to_numeric, errors='coerce')

    df = df.replace([np.inf, -np.inf], np.nan).fillna(0)

    return df


# =====
# 2. SPLIT DATA (IMPORTANT FOR PAPERS)
# =====
def split_data(df):
    X = df.drop(columns=["label"])
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=0.3,
        random_state=42,
        stratify=y
    )

    return X_train, X_test, y_train, y_test


# =====
# 3. BASELINE MODEL (RANDOM FOREST)
# =====
def random_forest_model(X_train, X_test, y_train):

    rf = RandomForestClassifier(
        n_estimators=150,
        max_depth=20,
        random_state=42,
        n_jobs=-1
    )

    rf.fit(X_train, y_train)
    preds = rf.predict(X_test)
    probs = rf.predict_proba(X_test)[:, 1]

    return preds, probs, rf


# =====
# 4. UNSUPERVISED MODEL (ISOLATION FOREST)
# =====
def isolation_model(X_train, X_test):

    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s = scaler.transform(X_test)

    iso = IsolationForest(
        n_estimators=200,
        contamination=0.1,
        random_state=42
    )

    iso.fit(X_train_s)

    pred_raw = iso.predict(X_test_s)
    scores = iso.decision_function(X_test_s)

    preds = np.where(pred_raw == -1, 1, 0)

    return preds, scores


# =====
# 5. EVALUATION FUNCTION
# =====
def evaluate_model(name, y_true, preds, scores=None):

    print(f"\n===== {name} =====")

    print("\nConfusion Matrix:")
    print(confusion_matrix(y_true, preds))

    print("\nClassification Report:")
    print(classification_report(y_true, preds))

    if scores is not None:
        auc = roc_auc_score(y_true, scores)
        print("ROC-AUC:", auc)

        fpr, tpr, _ = roc_curve(y_true, scores)

        plt.plot(fpr, tpr, label=f"{name} AUC={auc:.3f}")


# =====
# 6. FEATURE IMPORTANCE (PAPER REQUIREMENT)
# =====
def plot_feature_importance(model, X_train):

    importances = model.feature_importances_
    features = X_train.columns

    idx = np.argsort(importances)[-15:]  # top 15

    plt.figure(figsize=(10, 6))
    plt.barh(range(len(idx)), importances[idx])
    plt.yticks(range(len(idx)), [features[i] for i in idx])
    plt.title("Top Feature Importance (Random Forest)")
    plt.show()


# =====
# 7. MAIN EXPERIMENT PIPELINE
# =====
def main():

    DATA_PATH = "archive"

    print("Loading dataset...")
    df = load_data(DATA_PATH)

    print("Splitting dataset...")
    X_train, X_test, y_train, y_test = split_data(df)

    # Scale for RF (optional but stable)
    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s = scaler.transform(X_test)

    # Convert back to DF for feature names
    X_train_s = pd.DataFrame(X_train_s, columns=X_train.columns)
    X_test_s = pd.DataFrame(X_test_s, columns=X_test.columns)

    # ================= RF MODEL =================
    rf_preds, rf_probs, rf_model = random_forest_model(
        X_train_s, X_test_s, y_train
    )

    # ================= ISOLATION FOREST =================
    iso_preds, iso_scores = isolation_model(X_train, X_test)

    # ================= EVALUATION =================
    evaluate_model("Random Forest (Supervised)", y_test, rf_preds, rf_probs)
    evaluate_model("Isolation Forest (Unsupervised)", y_test, iso_preds, iso_scores)

    # ================= FEATURE IMPORTANCE =================
    plot_feature_importance(rf_model, X_train_s)

    # ================= ROC FINAL PLOT =================
    plt.plot([0,1],[0,1],'--',color='gray')
    plt.xlabel("False Positive Rate")
    plt.ylabel("True Positive Rate")
    plt.title("ROC Comparison")
    plt.legend()
    plt.grid()
    plt.show()


if __name__ == "__main__":
    main()
 """


import pandas as pd
import numpy as np
import glob
import matplotlib.pyplot as plt

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    confusion_matrix,
    classification_report,
    roc_auc_score,
    roc_curve
)

from sklearn.ensemble import RandomForestClassifier, IsolationForest
from xgboost import XGBClassifier
from imblearn.over_sampling import SMOTE



# 1. LOAD + MEMORY SAFE SAMPLING

def load_data(folder, sample_size=300000):

    files = glob.glob(folder + "/*.csv")
    df_list = []

    for f in files:
        print("Loading:", f)
        df = pd.read_csv(f, low_memory=False)
        df.columns = df.columns.str.strip()

        label_col = None
        for c in df.columns:
            if c.lower() == "label":
                label_col = c
                break

        if label_col is None:
            continue

        df["label"] = df[label_col].apply(
            lambda x: 0 if str(x).strip().upper() == "BENIGN" else 1
        )

        df.drop(columns=[label_col], inplace=True)
        df_list.append(df)

    df = pd.concat(df_list, ignore_index=True)

    drop_cols = ["Flow ID", "Source IP", "Destination IP", "Timestamp"]
    df.drop(columns=[c for c in drop_cols if c in df.columns], inplace=True)

    df = df.apply(pd.to_numeric, errors='coerce')
    df.replace([np.inf, -np.inf], np.nan, inplace=True)

    #  MEMORY FIX: sample dataset
    if len(df) > sample_size:
        df = df.sample(sample_size, random_state=42)

    print("Final dataset shape:", df.shape)
    return df



# 2. PREPROCESSING (SAFE)

def preprocess(df):

    X = df.drop(columns=["label"])
    y = df["label"]

    imputer = SimpleImputer(strategy="median")
    X = imputer.fit_transform(X)

    return train_test_split(
        X, y,
        test_size=0.3,
        random_state=42,
        stratify=y
    )



# 3. MODELS (OPTIMIZED)

def train_models(X_train, X_test, y_train):

    # OPTIONAL SMOTE (safe now because dataset is small)
    sm = SMOTE(random_state=42)
    X_train, y_train = sm.fit_resample(X_train, y_train)

    #  RANDOM FOREST 
    rf = RandomForestClassifier(
        n_estimators=80,
        max_depth=15,
        n_jobs=-1,
        random_state=42
    )
    rf.fit(X_train, y_train)
    rf_pred = rf.predict(X_test)
    rf_prob = rf.predict_proba(X_test)[:, 1]

    #  XGBOOST 
    xgb = XGBClassifier(
        n_estimators=120,
        max_depth=5,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        eval_metric="logloss",
        n_jobs=-1
    )
    xgb.fit(X_train, y_train)
    xgb_pred = xgb.predict(X_test)
    xgb_prob = xgb.predict_proba(X_test)[:, 1]

    #  ISOLATION FOREST 
    iso = IsolationForest(
        n_estimators=100,
        contamination=0.1,
        random_state=42
    )
    iso.fit(X_train)

    iso_pred = np.where(iso.predict(X_test) == -1, 1, 0)
    iso_score = iso.decision_function(X_test)

    return rf_pred, rf_prob, xgb_pred, xgb_prob, iso_pred, iso_score



# 4. EVALUATION

def evaluate(name, y_true, pred, score=None):

    print("\n")
    print(name)
    print("")

    print(confusion_matrix(y_true, pred))
    print(classification_report(y_true, pred))

    auc = None
    if score is not None:
        auc = roc_auc_score(y_true, score)
        print("ROC-AUC:", auc)

        fpr, tpr, _ = roc_curve(y_true, score)
        plt.plot(fpr, tpr, label=f"{name} AUC={auc:.3f}")

    return auc



# 5. MAIN PIPELINE

def main():

    df = load_data("archive")

    X_train, X_test, y_train, y_test = preprocess(df)

    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)

    rf_p, rf_pr, xgb_p, xgb_pr, iso_p, iso_s = train_models(
        X_train, X_test, y_train
    )

    rf_auc = evaluate("Random Forest", y_test, rf_p, rf_pr)
    xgb_auc = evaluate("XGBoost ", y_test, xgb_p, xgb_pr)
    iso_auc = evaluate("Isolation Forest", y_test, iso_p, iso_s)

    # ROC curve
    plt.plot([0, 1], [0, 1], '--', color='gray')
    plt.xlabel("FPR")
    plt.ylabel("TPR")
    plt.title("ROC Comparison")
    plt.legend()
    plt.grid()
    plt.show()

    # comparison chart
    plt.figure()
    plt.bar(["RF", "XGB", "ISO"], [rf_auc, xgb_auc, iso_auc])
    plt.title("Model Comparison (ROC-AUC)")
    plt.ylabel("AUC")
    plt.show()


if __name__ == "__main__":
    main()