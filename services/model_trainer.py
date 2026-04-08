# services/model_trainer.py
"""
Training pipeline for XGBoost signal model.
Uses historical signals + trade outcomes to train the model.

Usage: python services/model_trainer.py
"""
import os
import sys
import logging
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import numpy as np
from database.db_conn import execute_query_all
from services.xgboost_model import XGBoostSignalModel, FEATURE_NAMES, MODEL_DIR, MODEL_PATH

logger = logging.getLogger(__name__)

MIN_SAMPLES = 50


def build_training_data():
    """
    Pull historical signals + trade results from DB.
    Returns (X, y) where X = feature arrays, y = labels (1=LONG win, -1=SHORT win, 0=loss/neutral).
    """
    rows = execute_query_all("""
        SELECT s.symbol, s.signal, s.confidence, s.entry_price, s.stop_loss, s.take_profit,
               s.timeframe, s.reasoning, s.created_at,
               t.status as trade_status, t.profit_loss
        FROM signals s
        LEFT JOIN trades t ON (t.decision_details->>'signal_id')::int = s.id
        WHERE s.signal IN ('LONG', 'SHORT')
          AND s.created_at > NOW() - INTERVAL '90 days'
        ORDER BY s.created_at DESC
    """)

    if not rows or len(rows) < MIN_SAMPLES:
        logger.warning(f"Only {len(rows) if rows else 0} samples found, need {MIN_SAMPLES} minimum")
        return None, None

    X = []
    y = []

    for row in rows:
        trade_status = row.get('trade_status')
        if trade_status is None:
            continue

        label = 0
        if trade_status == 'won':
            label = 1 if row['signal'] == 'LONG' else -1
        elif trade_status == 'lost':
            label = 0

        if label == 0 and trade_status is None:
            continue

        features = _extract_features_from_row(row)
        if features:
            X.append(features)
            y.append(label)

    if len(X) < MIN_SAMPLES:
        logger.warning(f"Only {len(X)} usable samples after filtering")
        return None, None

    logger.info(f"Training data: {len(X)} samples, {sum(1 for v in y if v == 1)} LONG wins, "
                f"{sum(1 for v in y if v == -1)} SHORT wins, {sum(1 for v in y if v == 0)} losses")

    return np.array(X), np.array(y)


def _extract_features_from_row(row):
    """Extract features from a signal row. Uses reasoning JSON if available."""
    import json

    reasoning = row.get('reasoning', '')
    entry = row.get('entry_price', 0) or 0
    if entry <= 0:
        return None

    features = {}
    for name in FEATURE_NAMES:
        features[name] = 0.0

    features['rsi_14'] = 50.0
    features['price_change_pct'] = 0.0

    if reasoning:
        try:
            data = json.loads(reasoning)
            if isinstance(data, dict):
                for key in data:
                    if key in FEATURE_NAMES:
                        val = data[key]
                        if isinstance(val, (int, float)):
                            features[key] = float(val)
        except (json.JSONDecodeError, TypeError):
            pass

    return [features[f] for f in FEATURE_NAMES]


def train_model():
    """Train XGBoost model and save to disk."""
    try:
        import xgboost as xgb
        from sklearn.model_selection import train_test_split
        from sklearn.metrics import accuracy_score, classification_report
        import joblib
    except ImportError:
        logger.error("Missing dependencies. Run: pip install xgboost scikit-learn joblib")
        return False

    X, y = build_training_data()
    if X is None or y is None:
        logger.warning("Not enough data to train model. Using rules-based fallback.")
        return False

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    model = xgb.XGBClassifier(
        n_estimators=100,
        max_depth=4,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        random_state=42,
        eval_metric='mlogloss',
        use_label_encoder=False,
    )

    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    logger.info(f"Model accuracy: {acc:.2%}")
    logger.info(classification_report(y_test, y_pred, zero_division=0))

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, str(MODEL_PATH))
    logger.info(f"Model saved to {MODEL_PATH}")

    return True


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    success = train_model()
    if success:
        print("Model trained and saved successfully!")
    else:
        print("Model training skipped — not enough data or missing dependencies.")
