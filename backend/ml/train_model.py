import os
import json
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report
)
import joblib

# Paths
BASE_DIR = Path(__file__).resolve().parent.parent.parent
DATA_PATH = BASE_DIR / "data" / "phishing_corpus.json"
MODELS_DIR = BASE_DIR / "backend" / "ml" / "models"
MODELS_DIR.mkdir(parents=True, exist_ok=True)
MODEL_SAVE_PATH = MODELS_DIR / "phishguard_pipeline.joblib"
METRICS_SAVE_PATH = MODELS_DIR / "evaluation_metrics.json"

def load_and_preprocess_data(file_path=DATA_PATH):
    """Loads, cleans, and deduplicates the training corpus."""
    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    df = pd.DataFrame(data)
    # Deduplicate on text
    initial_len = len(df)
    df = df.drop_duplicates(subset=['text']).reset_index(drop=True)
    print(f"[*] Loaded {len(df)} unique samples (stripped {initial_len - len(df)} duplicates).")
    return df

def train_and_evaluate():
    """
    Reproducible ML Training Pipeline:
    - Stratified splitting (Train 70%, Val 15%, Test 15%)
    - Text vectorization with sublinear TF-IDF
    - Compares Logistic Regression vs Random Forest
    - Serializes champion model and records performance metrics
    """
    df = load_and_preprocess_data()
    X = df['text']
    y = df['label']

    # Stratified Split: 70% Train, 30% Temp (Val + Test)
    X_train, X_temp, y_train, y_temp = train_test_split(
        X, y, test_size=0.30, random_state=42, stratify=y
    )

    # Split Temp into 15% Val and 15% Test
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp, test_size=0.50, random_state=42, stratify=y_temp
    )

    print(f"[*] Data Splits: Train={len(X_train)}, Val={len(X_val)}, Test={len(X_test)}")

    # Candidate 1: Logistic Regression Pipeline
    pipe_lr = Pipeline([
        ('tfidf', TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True, lowercase=True)),
        ('clf', LogisticRegression(C=1.0, max_iter=1000, random_state=42))
    ])

    # Candidate 2: Random Forest Pipeline
    pipe_rf = Pipeline([
        ('tfidf', TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True, lowercase=True)),
        ('clf', RandomForestClassifier(n_estimators=100, max_depth=15, random_state=42))
    ])

    candidates = {
        'Logistic Regression': pipe_lr,
        'Random Forest': pipe_rf
    }

    results = {}
    best_model_name = None
    best_f1 = -1.0
    best_pipeline = None

    for name, pipeline in candidates.items():
        print(f"\n[*] Training candidate model: {name}...")
        pipeline.fit(X_train, y_train)

        # Validation set evaluation
        y_val_pred = pipeline.predict(X_val)
        val_f1 = f1_score(y_val, y_val_pred, zero_division=0)
        print(f"    Validation F1-Score: {val_f1:.4f}")

        # Test set evaluation
        y_test_pred = pipeline.predict(X_test)
        acc = accuracy_score(y_test, y_test_pred)
        prec = precision_score(y_test, y_test_pred, zero_division=0)
        rec = recall_score(y_test, y_test_pred, zero_division=0)
        f1 = f1_score(y_test, y_test_pred, zero_division=0)
        cm = confusion_matrix(y_test, y_test_pred)

        tn, fp, fn, tp = cm.ravel()
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

        results[name] = {
            'accuracy': round(float(acc), 4),
            'precision': round(float(prec), 4),
            'recall': round(float(rec), 4),
            'f1': round(float(f1), 4),
            'confusion_matrix': {
                'true_negatives': int(tn),
                'false_positives': int(fp),
                'false_negatives': int(fn),
                'true_positives': int(tp)
            },
            'false_positive_rate': round(float(fpr), 4),
            'false_negative_rate': round(float(fnr), 4)
        }

        if f1 > best_f1:
            best_f1 = f1
            best_model_name = name
            best_pipeline = pipeline

    print(f"\n[+] Champion Model Selected: {best_model_name} (Test F1 = {best_f1:.4f})")

    # Serialize champion pipeline
    joblib.dump(best_pipeline, MODEL_SAVE_PATH)
    print(f"[+] Saved model pipeline to: {MODEL_SAVE_PATH}")

    # Build evaluation report
    report = {
        'selected_model': best_model_name,
        'dataset_sample_count': len(df),
        'train_samples': len(X_train),
        'test_samples': len(X_test),
        'accuracy': results[best_model_name]['accuracy'],
        'precision': results[best_model_name]['precision'],
        'recall': results[best_model_name]['recall'],
        'f1': results[best_model_name]['f1'],
        'confusion_matrix': results[best_model_name]['confusion_matrix'],
        'candidate_models_comparison': results
    }

    with open(METRICS_SAVE_PATH, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2)
    print(f"[+] Saved evaluation telemetry to: {METRICS_SAVE_PATH}")

    return report

if __name__ == "__main__":
    train_and_evaluate()
