"""
Model factory + artifact I/O for the phishing classifier.
Builds a TF-IDF+URL featurizer and logistic regression, then saves/loads
their joblib artifacts for runtime use.
"""
from typing import Dict, Any
from sklearn.linear_model import LogisticRegression
from joblib import dump, load
from .features import TextURLFeaturizer

# pylint: disable=too-many-arguments
def build_model(cfg: Dict[str, Any]):
    """Build TF-IDF+URL featurizer and logistic regression classifier from config."""
    pcfg = cfg["phishing"]
    fcfg = pcfg["features"]
    mcfg = pcfg["model"]

    # Build featurizer
    featurizer = TextURLFeaturizer(
        vocab_size=fcfg.get("vocab_size", 30000),
        ngram_range=tuple(fcfg.get("ngram_range", [1,2])),
        min_df=fcfg.get("min_df", 2),
        max_df=fcfg.get("max_df", 0.9),
        lowercase=fcfg.get("lowercase", True),
        strip_html=fcfg.get("strip_html", True),
        include_url_features=fcfg.get("include_url_features", True),
    )

    # Build classifier
    if mcfg.get("type", "logistic_regression") != "logistic_regression":
        raise NotImplementedError("Only logistic_regression implemented.")

    # Build logistic regression classifier
    clf = LogisticRegression(
        C=mcfg.get("C", 2.0),
        class_weight=mcfg.get("class_weight", "balanced"),
        max_iter=mcfg.get("max_iter", 200)
    )
    return {"featurizer": featurizer, "clf": clf}

# pylint: enable=too-many-arguments
def save_artifacts(pipe, artifacts_dir: str):
    """Persist featurizer and classifier to joblib files."""
    dump(pipe["featurizer"], f"{artifacts_dir}/vectorizer.joblib")
    dump(pipe["clf"], f"{artifacts_dir}/model.joblib")

# pylint: disable=broad-except
def load_artifacts(artifacts_dir: str):
    """Load model artifacts and align featurizer expected feature count."""
    featurizer = load(f"{artifacts_dir}/vectorizer.joblib")
    clf = load(f"{artifacts_dir}/model.joblib")
    expected = getattr(clf, "n_features_in_", None)

    # Align expected feature count if possible
    if expected is not None and hasattr(featurizer, "__setattr__"):
        try:
            # Keep vectorizer and classifier in sync when sklearn tracks feature count.
            featurizer.expected_total_features = expected
        except Exception:
            pass
    return {"featurizer": featurizer, "clf": clf}
