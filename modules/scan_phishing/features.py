import re, numpy as np
from scipy.sparse import csr_matrix, hstack
from sklearn.feature_extraction.text import TfidfVectorizer

TAG_RE = re.compile(r"<[^>]+>")
URL_RE = re.compile(r"https?://[^\s)>\"]+", re.I)

def _strip_html(x: str) -> str:
    return TAG_RE.sub(" ", x or "")

def _normalize_texts(X) -> np.ndarray:
    """
    Return a 1-D numpy array of stringified texts for downstream processing.
    Accepts pandas objects, numpy arrays, sequences, and scalars.
    """
    if isinstance(X, (str, bytes)):
        arr = np.array([X], dtype=object)
    else:
        if hasattr(X, "to_numpy"):
            X = X.to_numpy()
        arr = np.asarray(X, dtype=object)
        if arr.ndim == 0:
            arr = arr.reshape(1)
    arr = arr.ravel()
    normalized = []
    for raw in arr:
        if isinstance(raw, str):
            normalized.append(raw)
        elif raw is None:
            normalized.append("")
        else:
            normalized.append(str(raw))
    return np.asarray(normalized, dtype=object)

class UrlFeatures:
    def fit(self, X, y=None): return self
    def transform(self, X):
        arr = _normalize_texts(X)
        rows = []
        for raw in arr:
            txt = raw
            urls = URL_RE.findall(txt) if txt else []
            hosts = [u.split("://",1)[-1].split("/",1)[0].lower() for u in urls]
            url_count = float(len(urls))
            unique_domains = float(len(set(hosts)))
            has_login = 1.0 if re.search(r"(login|verify|update|reset)", txt, re.I) else 0.0
            has_ip = 1.0 if any(re.match(r"\d+\.\d+\.\d+\.\d+", h) for h in hosts) else 0.0
            rows.append([url_count, unique_domains, has_login, has_ip])
        if rows:
            features = np.asarray(rows, dtype=np.float32)
        else:
            # Preserve expected column count even when the input is empty.
            features = np.zeros((int(arr.size), 4), dtype=np.float32)
        return csr_matrix(features)

class TextURLFeaturizer:
    """
    TfidfVectorizer wrapper that optionally augments text features with URL-derived features.
    Stored attributes align with historical joblib artifacts: vectorizer, lowercase,
    strip_html, include_url_features.
    """

    def __init__(
        self,
        vocab_size: int | None = None,
        ngram_range=(1, 2),
        min_df: int = 2,
        max_df: float = 0.9,
        lowercase: bool = True,
        strip_html: bool = True,
        include_url_features: bool = True,
    ):
        self.vocab_size = vocab_size
        self.ngram_range = ngram_range
        self.min_df = min_df
        self.max_df = max_df
        self.lowercase = lowercase
        self.strip_html = strip_html
        self.include_url_features = include_url_features
        self.vectorizer = self._create_vectorizer()
        self.expected_total_features = None

    def _create_vectorizer(self) -> TfidfVectorizer:
        max_features = self.vocab_size if (self.vocab_size and self.vocab_size > 0) else None
        return TfidfVectorizer(
            max_features=max_features,
            ngram_range=self.ngram_range,
            min_df=self.min_df,
            max_df=self.max_df,
            lowercase=self.lowercase,
            dtype=np.float32,
        )

    def _preprocess(self, texts: np.ndarray) -> np.ndarray:
        if not self.strip_html:
            return texts
        return np.asarray([_strip_html(t) for t in texts], dtype=object)

    def fit(self, X, y=None):
        texts = _normalize_texts(X)
        processed = self._preprocess(texts)
        self.vectorizer.fit(processed, y)
        self.expected_total_features = len(self.vectorizer.vocabulary_) + (4 if self.include_url_features else 0)
        return self

    def transform(self, X):
        texts = _normalize_texts(X)
        processed = self._preprocess(texts)
        X_tfidf = self.vectorizer.transform(processed)
        if self.include_url_features:
            X_url = UrlFeatures().transform(texts)
            X_combined = hstack([X_tfidf, X_url], format="csr")
        else:
            X_combined = X_tfidf
        expected = getattr(self, "expected_total_features", None)
        if expected is not None and X_combined.shape[1] != expected:
            diff = expected - X_combined.shape[1]
            if diff > 0:
                pad = csr_matrix((X_combined.shape[0], diff), dtype=X_combined.dtype)
                X_combined = hstack([X_combined, pad], format="csr")
            elif diff < 0:
                X_combined = X_combined[:, :expected]
        return X_combined

    def fit_transform(self, X, y=None):
        texts = _normalize_texts(X)
        processed = self._preprocess(texts)
        X_tfidf = self.vectorizer.fit_transform(processed, y)
        if self.include_url_features:
            X_url = UrlFeatures().transform(texts)
            X_combined = hstack([X_tfidf, X_url], format="csr")
        else:
            X_combined = X_tfidf
        self.expected_total_features = X_combined.shape[1]
        expected = getattr(self, "expected_total_features", None)
        if expected is not None and X_combined.shape[1] != expected:
            diff = expected - X_combined.shape[1]
            if diff > 0:
                pad = csr_matrix((X_combined.shape[0], diff), dtype=X_combined.dtype)
                X_combined = hstack([X_combined, pad], format="csr")
            elif diff < 0:
                X_combined = X_combined[:, :expected]
        return X_combined

    # Joblib backward compatibility: ensure vectorizer exists after unpickling older objects.
    def __getstate__(self):
        return self.__dict__

    def __setstate__(self, state):
        self.__dict__.update(state)
        if "vectorizer" not in self.__dict__ or self.vectorizer is None:
            self.vectorizer = self._create_vectorizer()
        if "expected_total_features" not in self.__dict__ or self.expected_total_features is None:
            vocab = len(getattr(self.vectorizer, "vocabulary_", {}) or {})
            url_dims = 4 if self.include_url_features else 0
            self.expected_total_features = vocab + url_dims

def build_featurizer(pcfg):
    fcfg = pcfg.get("features", {})
    ngram_range = tuple(fcfg.get("ngram_range", [1,2]))
    min_df = fcfg.get("min_df", 2)
    max_df = fcfg.get("max_df", 0.9)
    lowercase = bool(fcfg.get("lowercase", True))
    strip_html = bool(fcfg.get("strip_html", True))
    include_url = bool(fcfg.get("include_url_features", True))

    def fit_transform(texts):
        featurizer = TextURLFeaturizer(
            vocab_size=fcfg.get("vocab_size"),
            ngram_range=ngram_range,
            min_df=min_df,
            max_df=max_df,
            lowercase=lowercase,
            strip_html=strip_html,
            include_url_features=include_url,
        )
        X = featurizer.fit_transform(texts)
        return (featurizer, featurizer.include_url_features), X

    def transform(texts, fitted_tuple):
        featurizer, _ = fitted_tuple
        return featurizer.transform(texts)

    return fit_transform, transform
