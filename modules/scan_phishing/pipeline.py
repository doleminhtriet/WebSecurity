from pathlib import Path
import json
import warnings
import pandas as pd
from joblib import dump, load
from sklearn.linear_model import LogisticRegression
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import classification_report, average_precision_score, precision_recall_curve
import numpy as np

from .features import build_featurizer

def _read(csv_path, text_col, label_col):
    df = pd.read_csv(csv_path)
    if text_col not in df.columns or label_col not in df.columns:
        raise ValueError(f"{csv_path} must have columns '{text_col}' and '{label_col}'")
    return df[text_col].astype(str).fillna(""), df[label_col].astype(int).to_numpy()

def save_artifacts(vec, clf, artifacts_dir: str):
    d = Path(artifacts_dir); d.mkdir(parents=True, exist_ok=True)
    dump(vec, d / "vectorizer.joblib")
    dump(clf, d / "model.joblib")

def load_artifacts(artifacts_dir: str):
    d = Path(artifacts_dir)
    featurizer = load(d / "vectorizer.joblib")
    clf = load(d / "model.joblib")
    expected = getattr(clf, "n_features_in_", None)
    if expected is not None:
        try:
            featurizer.expected_total_features = expected
        except Exception:
            pass
    return {
        "featurizer": featurizer,
        "clf": clf,
    }

def train(cfg):
    pcfg, dcfg = cfg["phishing"], cfg["phishing"]["data"]
    artifacts = Path(pcfg.get("artifacts_dir", "modules/scan_phishing/artifacts"))
    artifacts.mkdir(parents=True, exist_ok=True)

    Xtr_text, ytr = _read(dcfg["train_csv"], dcfg["text_column"], dcfg["label_column"])
    Xva_text, yva = _read(dcfg["valid_csv"], dcfg["text_column"], dcfg["label_column"])

    fit_transform, transform = build_featurizer(pcfg)
    fitted_vec, Xtr = fit_transform(Xtr_text)
    Xva = transform(Xva_text, fitted_vec)

    mc = pcfg.get("model", {})
    base = LogisticRegression(
        C=mc.get("C", 2.0),
        class_weight=mc.get("class_weight", "balanced"),
        max_iter=mc.get("max_iter", 200),
    )
    # Ensure calibration folds do not exceed the minority-class count.
    labels, counts = np.unique(ytr, return_counts=True)
    if counts.size < 2:
        raise ValueError("Training data must contain at least two classes.")
    minority = counts.min()
    if minority < 3:
        warnings.warn(
            f"Only {minority} samples in the smallest class; skipping 3-fold calibration.",
            RuntimeWarning,
        )
    if minority >= 2:
        cv_folds = max(2, min(3, int(minority)))
        clf = CalibratedClassifierCV(base, method="sigmoid", cv=cv_folds).fit(Xtr, ytr)
        calibration_info = {"cv_folds": cv_folds, "calibrated": True}
    else:
        clf = base.fit(Xtr, ytr)
        calibration_info = {"cv_folds": 0, "calibrated": False}

    # Eval
    prob = clf.predict_proba(Xva)[:,1]
    thr = float(pcfg.get("threshold", 0.5))
    pred = (prob >= thr).astype(int)
    pr_auc = float(average_precision_score(yva, prob))
    report = classification_report(yva, pred, output_dict=True, zero_division=0)

    # Suggest threshold (max F1)
    p, r, th = precision_recall_curve(yva, prob)
    f1 = (2*p*r) / np.clip(p+r, 1e-9, None)
    best_idx = int(np.nanargmax(f1))
    best_thr = float(0.0 if best_idx >= len(th) else th[best_idx])

    # Save
    save_artifacts(fitted_vec[0], clf, str(artifacts))
    metrics = {
        "pr_auc": pr_auc,
        "report": report,
        "suggested_threshold_f1": best_thr,
        "calibration": calibration_info,
        "class_counts": dict(zip(map(int, labels), map(int, counts))),
    }
    (artifacts / "metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    return metrics

def evaluate(cfg):
    pcfg, dcfg = cfg["phishing"], cfg["phishing"]["data"]
    artifacts = Path(pcfg.get("artifacts_dir", "modules/scan_phishing/artifacts"))
    vec = load(artifacts / "vectorizer.joblib")
    clf = load(artifacts / "model.joblib")

    Xva_text, yva = _read(dcfg["valid_csv"], dcfg["text_column"], dcfg["label_column"])
    # Rebuild transform closure for fitted vec
    def transform(texts):
        from .features import UrlFeatures
        X_tfidf = vec.transform(texts)
        if pcfg.get("features", {}).get("include_url_features", True):
            X_url = UrlFeatures().transform(texts)
            from scipy.sparse import hstack
            return hstack([X_tfidf, X_url], format="csr")
        return X_tfidf

    Xva = transform(Xva_text)
    prob = clf.predict_proba(Xva)[:,1]
    thr = float(pcfg.get("threshold", 0.5))
    pred = (prob >= thr).astype(int)
    pr_auc = float(average_precision_score(yva, prob))
    report = classification_report(yva, pred, output_dict=True, zero_division=0)
    return {"pr_auc": pr_auc, "threshold": thr, "report": report}
