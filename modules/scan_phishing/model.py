from typing import Dict, Any
from sklearn.linear_model import LogisticRegression
from joblib import dump, load
from .features import TextURLFeaturizer

def build_model(cfg: Dict[str, Any]):
    pcfg = cfg["phishing"]
    fcfg = pcfg["features"]
    mcfg = pcfg["model"]

    featurizer = TextURLFeaturizer(
        vocab_size=fcfg.get("vocab_size", 30000),
        ngram_range=tuple(fcfg.get("ngram_range", [1,2])),
        min_df=fcfg.get("min_df", 2),
        max_df=fcfg.get("max_df", 0.9),
        lowercase=fcfg.get("lowercase", True),
        strip_html=fcfg.get("strip_html", True),
        include_url_features=fcfg.get("include_url_features", True),
    )

    if mcfg.get("type", "logistic_regression") != "logistic_regression":
        raise NotImplementedError("Only logistic_regression implemented.")

    clf = LogisticRegression(
        C=mcfg.get("C", 2.0),
        class_weight=mcfg.get("class_weight", "balanced"),
        max_iter=mcfg.get("max_iter", 200)
    )
    return {"featurizer": featurizer, "clf": clf}

def save_artifacts(pipe, artifacts_dir: str):
    dump(pipe["featurizer"], f"{artifacts_dir}/vectorizer.joblib")
    dump(pipe["clf"], f"{artifacts_dir}/model.joblib")

def load_artifacts(artifacts_dir: str):
    featurizer = load(f"{artifacts_dir}/vectorizer.joblib")
    clf = load(f"{artifacts_dir}/model.joblib")
    return {"featurizer": featurizer, "clf": clf}
