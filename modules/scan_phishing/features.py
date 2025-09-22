import re, numpy as np
from scipy.sparse import csr_matrix, hstack
from sklearn.feature_extraction.text import TfidfVectorizer

TAG_RE = re.compile(r"<[^>]+>")
URL_RE = re.compile(r"https?://[^\s)>\"]+", re.I)

def _strip_html(x: str) -> str:
    return TAG_RE.sub(" ", x or "")

class UrlFeatures:
    def fit(self, X, y=None): return self
    def transform(self, X):
        rows = []
        for txt in X.astype(str):
            urls = URL_RE.findall(txt) if txt else []
            hosts = [u.split("://",1)[-1].split("/",1)[0].lower() for u in urls]
            url_count = float(len(urls))
            unique_domains = float(len(set(hosts)))
            has_login = 1.0 if re.search(r"(login|verify|update|reset)", txt, re.I) else 0.0
            has_ip = 1.0 if any(re.match(r"\d+\.\d+\.\d+\.\d+", h) for h in hosts) else 0.0
            rows.append([url_count, unique_domains, has_login, has_ip])
        return csr_matrix(np.asarray(rows, dtype=np.float32))

def build_featurizer(pcfg):
    fcfg = pcfg.get("features", {})
    ngram_range = tuple(fcfg.get("ngram_range", [1,2]))
    min_df = fcfg.get("min_df", 2)
    max_df = fcfg.get("max_df", 0.9)
    lowercase = bool(fcfg.get("lowercase", True))
    strip_html = bool(fcfg.get("strip_html", True))
    include_url = bool(fcfg.get("include_url_features", True))

    def preprocess(x: str) -> str:
        return _strip_html(x) if strip_html else (x or "")

    tfidf = TfidfVectorizer(
        preprocessor=preprocess,
        ngram_range=ngram_range,
        min_df=min_df,
        max_df=max_df,
        lowercase=lowercase,
        dtype=np.float32,
    )

    def fit_transform(texts):
        X_tfidf = tfidf.fit_transform(texts)
        if include_url:
            X_url = UrlFeatures().fit(texts).transform(texts)
            return (tfidf, True), hstack([X_tfidf, X_url], format="csr")
        return (tfidf, False), X_tfidf

    def transform(texts, fitted_tuple):
        vec, has_url = fitted_tuple
        X_tfidf = vec.transform(texts)
        if has_url:
            X_url = UrlFeatures().transform(texts)
            return hstack([X_tfidf, X_url], format="csr")
        return X_tfidf

    return fit_transform, transform
