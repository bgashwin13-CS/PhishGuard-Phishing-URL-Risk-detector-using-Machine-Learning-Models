import json
import os
import time
import warnings

import joblib
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
)
from sklearn.calibration import CalibratedClassifierCV
from xgboost import XGBClassifier

from src.features import FEATURES, extract_url_features

warnings.filterwarnings("ignore")

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS = os.path.join(BASE, "models")
REPORTS = os.path.join(BASE, "reports")
DATA = os.path.join(BASE, "data", "PhiUSIIL_Phishing_URL_Dataset.csv")

os.makedirs(MODELS, exist_ok=True)
os.makedirs(REPORTS, exist_ok=True)


def get_data():
    print("Loading LOCAL PhiUSIIL dataset...")
    print("Dataset:", DATA)

    if not os.path.exists(DATA):
        raise FileNotFoundError(
            f"Dataset not found:\n{DATA}\n"
            "Place PhiUSIIL_Phishing_URL_Dataset.csv inside the data folder."
        )

    raw = pd.read_csv(DATA, low_memory=False)

    print(f"Dataset loaded successfully: {len(raw):,} rows")
    print("Columns found:", list(raw.columns))

    # Find URL column
    url_candidates = [
        c for c in raw.columns
        if c.strip().lower() in ["url", "website", "link"]
    ]

    if not url_candidates:
        raise RuntimeError(
            "URL column not found. Columns are: "
            + ", ".join(raw.columns)
        )

    url_col = url_candidates[0]

    # Find label column
    label_candidates = [
        c for c in raw.columns
        if c.strip().lower() in [
            "label", "class", "status", "target", "result"
        ]
    ]

    if not label_candidates:
        raise RuntimeError(
            "Label column not found. Columns are: "
            + ", ".join(raw.columns)
        )

    label_col = label_candidates[0]

    print("URL column:", url_col)
    print("Label column:", label_col)

    urls = raw[url_col].fillna("").astype(str)

    original_y = pd.to_numeric(
        raw[label_col], errors="coerce"
    ).fillna(1).astype(int)

    # PhiUSIIL:
    # 0 = phishing
    # 1 = legitimate
    # Our ML model:
    # 1 = phishing
    # 0 = legitimate
    y = (original_y == 0).astype(int)

    print("\nClass distribution:")
    print(y.value_counts())

    print("\nExtracting URL-only features...")
    print("This can take a few minutes.")

    rows = []

    total = len(urls)

    for i, url in enumerate(urls):
        rows.append(extract_url_features(url))

        if (i + 1) % 10000 == 0:
            print(
                f"Processed {i + 1:,} / {total:,} URLs"
            )

    X = pd.DataFrame(rows, columns=FEATURES)

    print("Feature extraction complete.")
    print("Feature matrix:", X.shape)

    return X, y


def evaluate(model, X, y):
    pred = model.predict(X)
    prob = model.predict_proba(X)[:, 1]

    return {
        "accuracy": float(accuracy_score(y, pred)),
        "precision": float(
            precision_score(y, pred, zero_division=0)
        ),
        "recall": float(
            recall_score(y, pred, zero_division=0)
        ),
        "f1": float(
            f1_score(y, pred, zero_division=0)
        ),
        "roc_auc": float(
            roc_auc_score(y, prob)
        ),
        "confusion_matrix":
            confusion_matrix(y, pred).tolist(),
    }


def latency(model, X, n=500):
    sample = X.iloc[:min(n, len(X))]

    start = time.perf_counter()

    for i in range(len(sample)):
        model.predict_proba(sample.iloc[[i]])

    elapsed = time.perf_counter() - start

    return (
        1000 * elapsed / max(1, len(sample))
    )


def main():

    X, y = get_data()

    print("\nCreating stratified 80/20 split...")

    Xtr, Xte, ytr, yte = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=42,
        stratify=y,
    )

    print("Training samples:", len(Xtr))
    print("Testing samples:", len(Xte))

    # RANDOM FOREST
    rf_base = RandomForestClassifier(
        n_estimators=300,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced_subsample",
    )

    print("\nTraining calibrated Random Forest...")

    rf = CalibratedClassifierCV(
        rf_base,
        method="sigmoid",
        cv=3,
    )

    rf.fit(Xtr, ytr)

    print("Random Forest training complete.")

    # XGBOOST
    xgb_base = XGBClassifier(
        n_estimators=350,
        max_depth=6,
        learning_rate=0.08,
        subsample=0.9,
        colsample_bytree=0.9,
        reg_lambda=1.0,
        objective="binary:logistic",
        eval_metric="logloss",
        random_state=42,
        n_jobs=-1,
    )

    print("\nTraining calibrated XGBoost...")

    xgb = CalibratedClassifierCV(
        xgb_base,
        method="sigmoid",
        cv=3,
    )

    xgb.fit(Xtr, ytr)

    print("XGBoost training complete.")

    results = {}

    print("\nEvaluating models...")

    for name, model in [
        ("Random Forest", rf),
        ("XGBoost", xgb),
    ]:

        metrics = evaluate(model, Xte, yte)

        metrics["mean_ms_per_url_model_only"] = float(
            latency(model, Xte)
        )

        results[name] = metrics

        print("\n", name)
        print(json.dumps(metrics, indent=2))

    print("\nSaving trained models...")

    joblib.dump(
        rf,
        os.path.join(
            MODELS,
            "random_forest.joblib",
        ),
    )

    joblib.dump(
        xgb,
        os.path.join(
            MODELS,
            "xgboost.joblib",
        ),
    )

    metadata = {
        "features": FEATURES,
        "positive_class": "phishing",
        "dataset":
            "PhiUSIIL Phishing URL Dataset",
        "feature_policy":
            "URL-only locally computable features",
        "split":
            "stratified 80/20, random_state=42",
        "score":
            "round(100*p)",
        "bands": {
            "low": "0-34",
            "suspicious": "35-69",
            "high": "70-100",
        },
    }

    with open(
        os.path.join(MODELS, "metadata.json"),
        "w",
    ) as f:
        json.dump(metadata, f, indent=2)

    with open(
        os.path.join(REPORTS, "metrics.json"),
        "w",
    ) as f:
        json.dump(results, f, indent=2)

    print("\n================================")
    print("TRAINING COMPLETE")
    print("================================")
    print("Models saved in models/")
    print("Metrics saved in reports/")
    print("\nNext:")
    print("Run .\\run_windows.bat")


if __name__ == "__main__":
    main()