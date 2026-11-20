"""Unsupervised anomaly detection ensemble (Isolation Forest + autoencoder).

The ensemble is fit on behavioral features extracted by :mod:`core.features`
without any labeled attack data:

* :class:`IsolationForest` — path-length based sparse outlier detector.
  ``score = -decision_function(X)`` (higher == more abnormal); the anomaly
  score is the min-max normalized range of this value on the training set.
* :class:`Autoencoder` — an undercomplete MLP (``MLPRegressor``) trained to
  reconstruct its input; the deviation score is the mean squared
  reconstruction error, normalized on the training range.

Sub-scores are combined into a single ``anomaly_score`` in ``[0, 1]``
(weighted by :attr:`AnomalyEngine.if_weight` / ``ae_weight``). Thresholds
are calibrated with the median-absolute-deviation (MAD) or contamination
quantile of the training scores, and :meth:`AnomalyEngine.predict` returns
per-feature Z-score attributions explaining which features drove the alert.
"""

from __future__ import annotations

import logging
import warnings
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Union

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.exceptions import ConvergenceWarning
from sklearn.neural_network import MLPRegressor
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger(__name__)


def severity_from_score(score: float) -> str:
    """Map a ``[0, 1]`` anomaly score to a severity level."""
    if score >= 0.9:
        return "critical"
    if score >= 0.7:
        return "high"
    if score >= 0.5:
        return "medium"
    return "low"


def dedupe_anomalies(
    df: pd.DataFrame,
    key_column: str = "anomaly_key",
    top_k: Optional[int] = None,
) -> pd.DataFrame:
    """Collapse near-duplicate anomalies: one row per ``key_column`` value,
    keeping the highest ``anomaly_score``, sorted best-first.

    Assigns a stable ``incident_id`` column (``INC-0001``, ``INC-0002``, ...).
    """
    if df is None or df.empty:
        out = df.copy() if df is not None else pd.DataFrame()
        out["incident_id"] = []
        return out.reset_index(drop=True)
    out = (
        df.sort_values("anomaly_score", ascending=False, kind="mergesort")
        .drop_duplicates(subset=[key_column], keep="first")
        .copy()
        .reset_index(drop=True)
    )
    if top_k is not None:
        out = out.head(int(top_k))
    out["incident_id"] = [f"INC-{i + 1:04d}" for i in range(len(out))]
    return out


class Autoencoder:
    """Minimal undercomplete MLP autoencoder trained with sklearn's MLPRegressor.

    The network reconstructs its input (``fit`` trains ``X -> ... -> X``);
    ``predict`` returns reconstructions and :meth:`reconstruction_error`
    returns the per-row MSE between input and reconstruction — the anomaly
    deviation signal.
    """

    def __init__(
        self,
        hidden_layers: Sequence[int] = (32, 16, 8),
        alpha: float = 0.0001,
        random_state: int = 42,
        max_iter: int = 500,
    ):
        self.regressor = MLPRegressor(
            hidden_layer_sizes=tuple(hidden_layers),
            alpha=alpha,
            solver="adam",
            activation="relu",
            random_state=random_state,
            max_iter=max_iter,
            n_iter_no_change=30,
            tol=1e-7,
            learning_rate_init=0.001,
        )
        self._is_fitted = False

    def fit(self, X: np.ndarray) -> "Autoencoder":
        # MLPRegressor is supervised: train the input->input mapping (autoencoder).
        # Convergence on tiny corpora is not required for reconstruction error.
        X = np.asarray(X, dtype=float)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", ConvergenceWarning)
            self.regressor.fit(X, X)
        self._is_fitted = True
        return self

    def _reconstruct(self, X: np.ndarray) -> np.ndarray:
        X = np.asarray(X, dtype=float)
        recon = self.regressor.predict(X)
        return np.asarray(recon, dtype=float).reshape(X.shape)

    def predict(self, X: np.ndarray) -> np.ndarray:
        if not self._is_fitted:
            raise RuntimeError("Autoencoder is not fitted")
        return self._reconstruct(X)

    def reconstruction_error(self, X: np.ndarray) -> np.ndarray:
        """Per-row mean squared reconstruction error (the anomaly signal)."""
        X = np.asarray(X, dtype=float)
        recon = self._reconstruct(X)
        return np.mean((X - recon) ** 2, axis=1)


class AnomalyEngine:
    """Unsupervised Isolation Forest + autoencoder anomaly ensemble.

    * ``fit(df)`` — trains the scaler, both submodels and calibrates the
      threshold on the training scores.
    * ``subscores(df)`` — per-row ``isf_score``, ``ae_score`` (both in
      ``[0, 1]``) and combined ``anomaly_score``.
    * ``predict(df)`` — :meth:`subscores` plus ``is_anomaly`` flags and
      per-feature Z-score attributions.
    """

    def __init__(
        self,
        contamination: float = 0.05,
        threshold_method: str = "mad",
        if_weight: float = 0.6,
        ae_weight: float = 0.4,
        mad_k: float = 2.5,
        random_state: int = 42,
        n_estimators: int = 200,
        n_jobs: int = -1,
    ):
        self.contamination = float(contamination)
        self.threshold_method = threshold_method
        self.if_weight = float(if_weight)
        self.ae_weight = float(ae_weight)
        self.mad_k = float(mad_k)
        self.random_state = random_state
        self.n_estimators = int(n_estimators)
        self.n_jobs = n_jobs
        self.is_fitted_ = False

    # ------------------------------------------------------------------ fit
    def fit(self, df: pd.DataFrame) -> "AnomalyEngine":
        if df is None or df.empty:
            raise ValueError("cannot train AnomalyEngine on an empty frame")
        self.feature_columns_: List[str] = list(df.columns)
        X = df.to_numpy(dtype=float)
        self.normalizer_ = StandardScaler().fit(X)
        Xs = self.normalizer_.transform(X)

        # Z-score reference statistics (for feature attribution).
        self.train_means_: np.ndarray = np.mean(X, axis=0)
        self.train_stds_: np.ndarray = np.std(X, axis=0)
        self.train_stds_ = np.where(self.train_stds_ <= 0, 1.0, self.train_stds_)

        # Isolation Forest: score = -decision_function, min-max normalized
        # on the training range.
        self.if_ = IsolationForest(
            n_estimators=self.n_estimators,
            max_samples="auto",
            contamination=self.contamination,
            random_state=self.random_state,
            n_jobs=self.n_jobs,
        )
        self.if_.fit(Xs)
        raw_if = -self.if_.decision_function(Xs)
        self._if_lo_ = float(np.min(raw_if))
        self._if_hi_ = float(np.max(raw_if))
        if self._if_hi_ <= self._if_lo_:
            self._if_hi_ = self._if_lo_ + 1e-9

        # Autoencoder: reconstruction MSE, min-max normalized on training range.
        self.ae_ = Autoencoder(random_state=self.random_state)
        self.ae_.fit(Xs)
        raw_mse = self.ae_.reconstruction_error(Xs)
        self._ae_lo_ = float(np.min(raw_mse))
        self._ae_hi_ = float(np.max(raw_mse))
        if self._ae_hi_ <= self._ae_lo_:
            self._ae_hi_ = self._ae_lo_ + 1e-9

        self.is_fitted_ = True
        self.train_subscores_ = self.subscores(df)
        self._calibrate_threshold()
        logger.info(
            "AnomalyEngine fit: %d events, %d features, threshold=%.4f",
            len(df),
            len(self.feature_columns_),
            self.threshold_,
        )
        return self

    def _check_fitted(self) -> None:
        if not self.is_fitted_ or not hasattr(self, "if_"):
            raise RuntimeError("AnomalyEngine is not fitted")

    # ------------------------------------------------------------- subscores
    def _frame_matrix(self, df: pd.DataFrame) -> np.ndarray:
        cols = self.feature_columns_
        if cols and all(c in df.columns for c in cols):
            return df[cols].to_numpy(dtype=float)
        return df.to_numpy(dtype=float)

    def subscores(self, df: pd.DataFrame) -> pd.DataFrame:
        """Per-row ``isf_score``, ``ae_score``, ``anomaly_score`` in ``[0, 1]``."""
        self._check_fitted()
        X = self._frame_matrix(df)
        Xs = self.normalizer_.transform(X)
        raw_if = -self.if_.decision_function(Xs)
        isf_score = np.clip((raw_if - self._if_lo_) / (self._if_hi_ - self._if_lo_), 0.0, 1.0)
        mse = self.ae_.reconstruction_error(Xs)
        ae_score = np.clip((mse - self._ae_lo_) / (self._ae_hi_ - self._ae_lo_), 0.0, 1.0)
        anomaly_score = self.if_weight * isf_score + self.ae_weight * ae_score
        return pd.DataFrame(
            {
                "isf_score": isf_score,
                "ae_score": ae_score,
                "anomaly_score": anomaly_score,
            },
            index=df.index,
        )

    # ---------------------------------------------------------------- predict
    def predict(self, df: pd.DataFrame) -> pd.DataFrame:
        """Return ``anomaly_score``, ``is_anomaly`` flags and Z-score attributions."""
        self._check_fitted()
        sub = self.subscores(df)
        scores = sub["anomaly_score"].to_numpy()
        out = pd.DataFrame(
            {
                "anomaly_score": scores,
                "isf_score": sub["isf_score"].to_numpy(),
                "ae_score": sub["ae_score"].to_numpy(),
                "is_anomaly": scores >= self.threshold_,
                "attributions": self._attributions(df),
            },
            index=df.index,
        )
        return out

    def _attributions(self, df: pd.DataFrame) -> List[List[Dict[str, Any]]]:
        """Top-5 per-feature Z-scores (train mean/std) for each row."""
        X = self._frame_matrix(df)
        denom = np.where(self.train_stds_ > 0, self.train_stds_, 1.0)
        z = (X - self.train_means_) / denom
        names = list(self.feature_columns_) if self.feature_columns_ else [f"f{i}" for i in range(X.shape[1])]
        top = 5
        out: List[List[Dict[str, Any]]] = []
        for i in range(X.shape[0]):
            idx = np.argsort(np.abs(z[i]))[::-1][:top]
            out.append(
                [
                    {"feature": names[j], "value": float(X[i][j]), "z": float(z[i][j])}
                    for j in idx
                    if j < len(names)
                ]
            )
        return out

    # ------------------------------------------------------------ threshold
    def _calibrate_threshold(self) -> None:
        scores = self.train_subscores_["anomaly_score"].to_numpy()
        if self.threshold_method == "quantile":
            self.threshold_ = float(np.quantile(scores, 1.0 - self.contamination))
        elif self.threshold_method == "mad":
            med = float(np.median(scores))
            mad = float(np.median(np.abs(scores - med))) * 1.4826
            self.threshold_ = float(med + self.mad_k * max(mad, 0.01))
        else:
            raise ValueError(f"unknown threshold method: {self.threshold_method!r}")
        self.threshold_ = float(np.clip(self.threshold_, 0.0, 1.0))

    # ------------------------------------------------------------------ io
    def save(self, path: Union[str, Path]) -> Path:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, p)
        return p

    @classmethod
    def load(cls, path: Union[str, Path]) -> "AnomalyEngine":
        engine = joblib.load(Path(path))
        if not engine.is_fitted_:
            raise ValueError(f"engine at {path} is not fitted")
        return engine
