# services/pretrain_xgboost.py
"""
Pretrains XGBoost model on recent historical data.
Fetches 500 candles per pair, simulates trades with SL/TP rules,
labels wins/losses, and trains the model.

Usage: python services/pretrain_xgboost.py
"""
import os
import sys
import logging
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent))

import numpy as np
from database.db_conn import execute_query, execute_query_all
from services.xgboost_model import XGBoostSignalModel, FEATURE_NAMES, MODEL_DIR, MODEL_PATH
from services.signal_engine import TechnicalIndicators, BINANCE_PUBLIC_URL, SIGNAL_PAIRS, SIGNAL_TIMEFRAMES

logger = logging.getLogger(__name__)

SL_PCT = 0.03
TP_PCT = 0.075
MIN_SAMPLES = 500


def fetch_klines(symbol: str, interval: str, limit: int = 500):
    """Fetch klines from Binance public API."""
    import requests
    url = f"{BINANCE_PUBLIC_URL}/fapi/v1/klines"
    params = {"symbol": symbol, "interval": interval, "limit": limit}
    try:
        resp = requests.get(url, params=params, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        return [
            {
                "open": float(k[1]), "high": float(k[2]), "low": float(k[3]),
                "close": float(k[4]), "volume": float(k[5]),
                "timestamp": k[0],
            }
            for k in data
        ]
    except Exception as e:
        logger.error(f"Failed to fetch klines for {symbol} {interval}: {e}")
        return []


def simulate_trade(klines: list, idx: int, side: str):
    """
    Simulate a trade starting at klines[idx].
    Returns: 1 (win), 0 (loss), -1 (neutral/no result within range)
    """
    entry = klines[idx]["close"]
    if side == "LONG":
        sl = entry * (1 - SL_PCT)
        tp = entry * (1 + TP_PCT)
    else:
        sl = entry * (1 + SL_PCT)
        tp = entry * (1 - TP_PCT)

    # Check next 100 candles for SL/TP hit
    for i in range(idx + 1, min(idx + 100, len(klines))):
        h, l = klines[i]["high"], klines[i]["low"]
        if side == "LONG":
            if l <= sl:
                return 0  # hit SL
            if h >= tp:
                return 1  # hit TP
        else:
            if h >= sl:
                return 0  # hit SL
            if l <= tp:
                return 1  # hit TP

    return -1  # no result within range


def build_features(closes, highs, lows, volumes, idx):
    """Extract features for candle at idx using trailing lookback."""
    lookback = 50
    start = max(0, idx - lookback)
    window_c = closes[start:idx+1]
    window_h = highs[start:idx+1]
    window_l = lows[start:idx+1]
    window_v = volumes[start:idx+1]

    if len(window_c) < 20:
        return None

    rsi = TechnicalIndicators.rsi(window_c, 14)
    ema9 = TechnicalIndicators.ema(window_c, 9)
    ema21 = TechnicalIndicators.ema(window_c, 21)
    ema50 = TechnicalIndicators.ema(window_c, 50)
    macd = TechnicalIndicators.macd(window_c)
    bb = TechnicalIndicators.bollinger_bands(window_c, 20)
    atr = TechnicalIndicators.atr(window_h, window_l, window_c, 14)
    sr = TechnicalIndicators.support_resistance(window_h, window_l, window_c)
    vwap = TechnicalIndicators.vwap(window_h, window_l, window_c, window_v)
    fvg = TechnicalIndicators.fair_value_gaps(window_c, window_h, window_l)
    liq = TechnicalIndicators.liquidity_sweeps(window_h, window_l, window_c)
    bos = TechnicalIndicators.break_of_structure(window_h, window_l, window_c)

    price = closes[idx]
    if price <= 0:
        return None

    def rel(val):
        if val is None:
            return 0.0
        return (val / price) - 1.0

    fvg_bull = sum(1 for f in fvg if f.get("type") == "bullish")
    fvg_bear = sum(1 for f in fvg if f.get("type") == "bearish")
    sweep = liq.get("sweep", "none")
    sweep_map = {"bullish": 1.0, "bearish": -1.0, "none": 0.0}
    bos_map = {"bullish_bos": 1.0, "bearish_bos": -1.0, "none": 0.0}

    vol_trend = 0.0
    if len(window_v) >= 10:
        avg_v = np.mean(window_v)
        recent_v = np.mean(window_v[-5:])
        if avg_v > 0:
            vol_trend = (recent_v / avg_v) - 1.0

    change_pct = ((closes[idx] - closes[max(0, idx-19)]) / closes[max(0, idx-19)]) * 100 if idx >= 19 else 0

    return {
        "rsi_14": float(rsi or 50.0),
        "ema_9_rel": rel(ema9),
        "ema_21_rel": rel(ema21),
        "ema_50_rel": rel(ema50),
        "macd_line": float(macd.get("macd_line", 0) if macd else 0),
        "macd_histogram": float(macd.get("histogram", 0) if macd else 0),
        "bb_upper_rel": rel(bb.get("upper") if bb else None),
        "bb_lower_rel": rel(bb.get("lower") if bb else None),
        "bb_bandwidth": float(bb.get("bandwidth", 0) if bb else 0),
        "atr_pct": float((atr / price) * 100 if atr else 0),
        "support_rel": rel(sr.get("support")),
        "resistance_rel": rel(sr.get("resistance")),
        "vwap_rel": rel(vwap),
        "price_change_pct": float(change_pct),
        "volume_trend": float(vol_trend),
        "fvg_bullish": float(fvg_bull),
        "fvg_bearish": float(fvg_bear),
        "liquidity_sweep": sweep_map.get(sweep, 0.0),
        "break_of_structure": bos_map.get(bos, 0.0),
    }


def collect_training_data():
    """Fetch historical data, simulate trades, build labeled dataset."""
    X = []
    y = []

    for symbol in SIGNAL_PAIRS:
        for tf in SIGNAL_TIMEFRAMES:
            logger.info(f"Fetching {symbol} {tf}...")
            klines = fetch_klines(symbol, tf, limit=500)
            if len(klines) < 100:
                continue

            closes = [k["close"] for k in klines]
            highs = [k["high"] for k in klines]
            lows = [k["low"] for k in klines]
            volumes = [k["volume"] for k in klines]

            for idx in range(50, len(klines) - 10):
                features = build_features(closes, highs, lows, volumes, idx)
                if features is None:
                    continue

                # Simulate both LONG and SHORT
                long_result = simulate_trade(klines, idx, "LONG")
                short_result = simulate_trade(klines, idx, "SHORT")

                if long_result == 1:
                    X.append([features[f] for f in FEATURE_NAMES])
                    y.append(0)  # 0 = LONG win
                elif short_result == 1:
                    X.append([features[f] for f in FEATURE_NAMES])
                    y.append(2)  # 2 = SHORT win
                elif long_result == 0 and short_result == 0:
                    X.append([features[f] for f in FEATURE_NAMES])
                    y.append(1)  # 1 = loss

    logger.info(f"Collected {len(X)} samples: {sum(1 for v in y if v==1)} LONG wins, "
                f"{sum(1 for v in y if v==-1)} SHORT wins, {sum(1 for v in y if v==0)} losses")
    return np.array(X), np.array(y)


def pretrain_model():
    """Pretrain XGBoost on historical data and save."""
    try:
        import xgboost as xgb
        from sklearn.model_selection import train_test_split
        from sklearn.metrics import accuracy_score, classification_report
        import joblib
    except ImportError:
        logger.error("Missing: pip install xgboost scikit-learn joblib")
        return False

    X, y = collect_training_data()
    if len(X) < MIN_SAMPLES:
        logger.warning(f"Only {len(X)} samples, need {MIN_SAMPLES}")
        return False

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    model = xgb.XGBClassifier(
        n_estimators=100,
        max_depth=4,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        random_state=42,
        eval_metric="mlogloss",
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


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    success = pretrain_model()
    print("Model pretrained!" if success else "Pretraining failed.")
