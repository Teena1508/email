#!/usr/bin/env python3
import os
import sys
import json
import joblib
import numpy as np
from pathlib import Path
from typing import Tuple, Dict, Any

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics import classification_report, confusion_matrix, precision_recall_fscore_support

# Ensure backend directory is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.ml.feature_extractor import FeatureExtractor, FEATURE_NAMES

SEVERITY_MAP = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
SEVERITY_NAMES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

def load_dataset(dataset_dir: str) -> Tuple[np.ndarray, np.ndarray, List[str]]:
    manifest_path = Path(dataset_dir) / "dataset_manifest.json"
    
    if not manifest_path.exists():
        print(f"[*] Synthetic dataset manifest missing at '{manifest_path}'. Generating dataset...")
        from app.synthetic.generator import SyntheticDatasetGenerator
        generator = SyntheticDatasetGenerator(dataset_dir)
        generator.generate(total_sessions=240)

    with open(manifest_path, "r") as f:
        manifest = json.load(f)

    X_list = []
    y_list = []
    attack_types = []

    for item in manifest["sessions"]:
        # Extract features
        X_vec = FeatureExtractor.extract_from_label_dict(item)
        sev_str = item.get("expected_severity", "LOW")
        y_val = SEVERITY_MAP.get(sev_str, 0)
        
        X_list.append(X_vec)
        y_list.append(y_val)
        attack_types.append(item.get("attack_type", "clean_baseline"))

    return np.array(X_list), np.array(y_list), attack_types

def train_models(models_dir: str, dataset_dir: Optional[str] = None) -> Tuple[RandomForestClassifier, IsolationForest]:
    if dataset_dir is None:
        dataset_dir = str(Path(__file__).resolve().parent.parent / "data" / "synthetic")

    models_path = Path(models_dir)
    models_path.mkdir(parents=True, exist_ok=True)

    X, y, attack_types = load_dataset(dataset_dir)

    # 80/20 Stratified Train/Test Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    # 1. Supervised Random Forest Classifier
    classifier = RandomForestClassifier(n_estimators=100, max_depth=8, random_state=42)
    classifier.fit(X_train, y_train)

    # 2. Unsupervised Isolation Forest Anomaly Detector (trained ONLY on clean_baseline)
    clean_indices = [i for i, att in enumerate(attack_types) if att == "clean_baseline"]
    if clean_indices:
        X_clean = X[clean_indices]
    else:
        X_clean = X_train[y_train == 0]

    anomaly_detector = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
    anomaly_detector.fit(X_clean)

    # Save trained model artifacts
    joblib.dump(classifier, models_path / "classifier.joblib")
    joblib.dump(anomaly_detector, models_path / "anomaly_detector.joblib")
    with open(models_path / "feature_names.json", "w") as f:
        json.dump(FEATURE_NAMES, f, indent=2)

    return classifier, anomaly_detector

def print_competition_writeup_eval(classifier: RandomForestClassifier, X_test: np.ndarray, y_test: np.ndarray):
    y_pred = classifier.predict(X_test)
    cm = confusion_matrix(y_test, y_pred, labels=[0, 1, 2, 3])

    prec, rec, f1, support = precision_recall_fscore_support(y_test, y_pred, labels=[0, 1, 2, 3])

    print("\n" + "="*70)
    print("  MODEL EVALUATION RESULTS (80/20 HELD-OUT TEST SPLIT)")
    print("="*70)
    print(f"{'Class':<12} | {'Precision':<10} | {'Recall':<10} | {'F1-Score':<10} | {'Support':<8}")
    print("-" * 62)

    for i, name in enumerate(SEVERITY_NAMES):
        p = prec[i] if i < len(prec) else 0.0
        r = rec[i] if i < len(rec) else 0.0
        f = f1[i] if i < len(f1) else 0.0
        s = support[i] if i < len(support) else 0
        print(f"{name:<12} | {p:<10.4f} | {r:<10.4f} | {f:<10.4f} | {s:<8}")

    print("-" * 62)
    macro_p = np.mean(prec)
    macro_r = np.mean(rec)
    macro_f1 = np.mean(f1)
    print(f"{'MACRO AVG':<12} | {macro_p:<10.4f} | {macro_r:<10.4f} | {macro_f1:<10.4f} | {len(y_test):<8}")
    print("="*70)

    print("\n[+] CONFUSION MATRIX (Actual rows vs Predicted columns):")
    print(" "*14 + "".join([f"{name:>10}" for name in SEVERITY_NAMES]))
    print("-" * 56)
    for i, name in enumerate(SEVERITY_NAMES):
        row_str = "".join([f"{cm[i][j]:>10}" for j in range(len(SEVERITY_NAMES))])
        print(f"{name:<12} |{row_str}")
    print("="*70 + "\n")

def main():
    backend_dir = Path(__file__).resolve().parent
    models_dir = str(backend_dir / "app" / "ml" / "saved_models")
    dataset_dir = str(backend_dir.parent / "data" / "synthetic")

    print("[+] Loading dataset and training Supervised & Unsupervised ML models...")
    X, y, attack_types = load_dataset(dataset_dir)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    classifier, anomaly_detector = train_models(models_dir, dataset_dir)
    print_competition_writeup_eval(classifier, X_test, y_test)
    print(f"[+] Trained model artifacts saved to '{models_dir}'.")

if __name__ == "__main__":
    main()
