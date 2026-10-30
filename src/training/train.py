"""
Train and compare the NSL-KDD detection models.

Run from the repository root after preprocessing:

    python src/training/preprocess.py
    python src/training/train.py                 # SVM only, the model used at runtime
    python src/training/train.py --models all    # also Random Forest, Gradient Boosting, MLP

Models are trained on KDDTrain+ and evaluated on KDDTest+, which contains
attack types that never appear in the training set.
"""

import argparse
import json
import os
import time
from datetime import datetime

import joblib
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.calibration import CalibratedClassifierCV
from sklearn.neural_network import MLPClassifier
from sklearn.svm import SVC


def load_processed_data():
    """Load preprocessed train/test sets."""
    x_train = pd.read_csv("data/processed/X_train.csv")
    x_test = pd.read_csv("data/processed/X_test.csv")
    y_train = pd.read_csv("data/processed/y_train.csv").squeeze("columns")
    y_test = pd.read_csv("data/processed/y_test.csv").squeeze("columns")
    return x_train, x_test, y_train, y_test


def evaluate(model, x_test, y_test):
    """Return standard IDS metrics for a trained model."""
    y_pred = model.predict(x_test)
    y_proba = model.predict_proba(x_test)[:, 1]

    metrics = {
        "accuracy": float(accuracy_score(y_test, y_pred)),
        "precision": float(precision_score(y_test, y_pred, zero_division=0)),
        "recall": float(recall_score(y_test, y_pred, zero_division=0)),
        "f1": float(f1_score(y_test, y_pred, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_test, y_proba)),
        "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
    }

    return metrics


MODEL_NAMES = ("svm", "random_forest", "gradient_boosting", "neural_network")


def build_models():
    """The four classifiers compared in the project."""
    return {
        "random_forest": RandomForestClassifier(
            n_estimators=200,
            max_depth=25,
            min_samples_split=10,
            min_samples_leaf=5,
            random_state=42,
            n_jobs=-1,
        ),
        "gradient_boosting": GradientBoostingClassifier(
            n_estimators=200,
            learning_rate=0.1,
            max_depth=7,
            min_samples_split=10,
            min_samples_leaf=5,
            subsample=0.8,
            random_state=42,
        ),
        # Platt-scaled RBF SVM (same as SVC(probability=True), which scikit-learn is deprecating)
        "svm": CalibratedClassifierCV(SVC(kernel="rbf", C=100, gamma="scale", random_state=42),
                                      method="sigmoid", cv=5, ensemble=False),
        "neural_network": MLPClassifier(
            hidden_layer_sizes=(128, 64, 32),
            max_iter=500,
            learning_rate_init=0.001,
            early_stopping=True,
            validation_fraction=0.1,
            random_state=42,
        ),
    }


def train_all_models(x_train, x_test, y_train, y_test, only=("svm",)):
    """Train the selected models and collect their test metrics."""
    models = {name: model for name, model in build_models().items() if name in only}
    all_results = {}
    os.makedirs("models", exist_ok=True)

    for name, model in models.items():
        print(f"\nTraining {name}...")
        start = time.time()
        model.fit(x_train, y_train)
        metrics = evaluate(model, x_test, y_test)
        metrics["train_seconds"] = round(time.time() - start, 1)
        all_results[name] = metrics

        joblib.dump(model, f"models/{name}_model.pkl")
        print(
            f"{name}: acc={metrics['accuracy']:.4f}, "
            f"prec={metrics['precision']:.4f}, rec={metrics['recall']:.4f}, "
            f"f1={metrics['f1']:.4f}, auc={metrics['roc_auc']:.4f}"
        )

    return all_results


def save_summary(all_results, y_train):
    """Save the comparison (merged with earlier runs) and a text report."""
    path = "models/model_results.json"
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            all_results = {**json.load(f), **all_results}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(all_results, f, indent=2)

    best_name = max(all_results.keys(), key=lambda key: all_results[key]["f1"])

    report_lines = [
        "=" * 60,
        "NSL-KDD IDS MODEL TRAINING REPORT",
        "=" * 60,
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        f"Train attack ratio: {float(y_train.mean()):.2%}",
        "",
        "MODEL PERFORMANCE",
        "-" * 60,
    ]

    for name, metrics in all_results.items():
        report_lines.extend(
            [
                f"\n{name}",
                f"  Accuracy : {metrics['accuracy']:.4f}",
                f"  Precision: {metrics['precision']:.4f}",
                f"  Recall   : {metrics['recall']:.4f}",
                f"  F1       : {metrics['f1']:.4f}",
                f"  ROC-AUC  : {metrics['roc_auc']:.4f}",
            ]
        )

    report_lines.extend(
        [
            "",
            "-" * 60,
            f"Best model by F1: {best_name}",
        ]
    )

    with open("models/training_report.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(report_lines))

    print(f"\nBest model by F1: {best_name}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train the NSL-KDD IDS models")
    parser.add_argument("--models", nargs="+", default=["svm"], choices=list(MODEL_NAMES) + ["all"])
    args = parser.parse_args()
    selected = MODEL_NAMES if "all" in args.models else tuple(args.models)

    x_train_data, x_test_data, y_train_data, y_test_data = load_processed_data()
    results = train_all_models(x_train_data, x_test_data, y_train_data, y_test_data, only=selected)
    save_summary(results, y_train_data)
    print("\nTraining complete. Artifacts saved in models/.")
