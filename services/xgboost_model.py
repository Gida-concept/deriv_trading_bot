# services/xgboost_model.py
import os
import logging
import numpy as np
from typing import Dict, Optional, List, Tuple
from pathlib import Path

logger = logging.getLogger(__name__)

FEATURE_NAMES = [
    'rsi_14',
    'ema_9_rel',
    'ema_21_rel',
    'ema_50_rel',
    'macd_line',
    'macd_histogram',
    'bb_upper_rel',
    'bb_lower_rel',
    'bb_bandwidth',
    'atr_pct',
    'support_rel',
    'resistance_rel',
    'vwap_rel',
    'price_change_pct',
    'volume_trend',
    'fvg_bullish',
    'fvg_bearish',
    'liquidity_sweep',
    'break_of_structure',
]

MODEL_DIR = Path(__file__).parent.parent / 'models'
MODEL_PATH = MODEL_DIR / 'xgboost_model.joblib'


class XGBoostSignalModel:
    """
    XGBoost-based signal predictor.
    Takes technical indicators as features, outputs signal + confidence.
    Falls back to rules-based scoring if model file is missing.
    """

    def __init__(self):
        self.model = None
        self._model_loaded = False
        self._load_model()

    def _load_model(self):
        try:
            if not MODEL_PATH.exists():
                logger.info("No trained XGBoost model found, using rules-based fallback")
                return

            import joblib
            self.model = joblib.load(str(MODEL_PATH))
            self._model_loaded = True
            logger.info(f"XGBoost model loaded from {MODEL_PATH}")

            # Verify xgboost is available
            import xgboost  # noqa: F401
        except ImportError:
            logger.warning("xgboost not installed, using rules-based fallback")
            self.model = None
        except Exception as e:
            logger.error(f"Failed to load XGBoost model: {e}")
            self.model = None

    def predict(self, indicators: Dict, current_price: float,
                price_change_pct: float, volumes: Optional[List[float]] = None) -> Dict:
        """
        Predict trading signal from technical indicators.

        Returns:
            {'signal': 'LONG'|'SHORT'|'NEUTRAL', 'confidence': 0-100}
        """
        features = self._extract_features(indicators, current_price,
                                          price_change_pct, volumes)

        if self._model_loaded and self.model is not None:
            return self._predict_with_model(features)

        return self._predict_rules_based(features)

    def _extract_features(self, indicators: Dict, current_price: float,
                          price_change_pct: float,
                          volumes: Optional[List[float]] = None) -> Dict[str, float]:
        """Convert indicators dict into normalized feature dict."""
        price = current_price if current_price > 0 else 1.0

        def rel(val):
            if val is None or price == 0:
                return 0.0
            return (val / price) - 1.0

        fvg_list = indicators.get('fair_value_gaps', [])
        fvg_bullish = sum(1 for f in fvg_list if f.get('type') == 'bullish')
        fvg_bearish = sum(1 for f in fvg_list if f.get('type') == 'bearish')

        liq_sweep = indicators.get('liquidity_sweep', {}).get('sweep', 'none')
        sweep_map = {'bullish': 1.0, 'bearish': -1.0, 'none': 0.0}

        bos = indicators.get('break_of_structure', 'none')
        bos_map = {'bullish_bos': 1.0, 'bearish_bos': -1.0, 'none': 0.0}

        volume_trend = 0.0
        if volumes and len(volumes) >= 10:
            recent_vol = np.mean(volumes[-5:])
            avg_vol = np.mean(volumes)
            if avg_vol > 0:
                volume_trend = (recent_vol / avg_vol) - 1.0

        return {
            'rsi_14': float(indicators.get('rsi_14', 50.0) or 50.0),
            'ema_9_rel': rel(indicators.get('ema_9')),
            'ema_21_rel': rel(indicators.get('ema_21')),
            'ema_50_rel': rel(indicators.get('ema_50')),
            'macd_line': float(indicators.get('macd', {}).get('macd_line', 0) or 0),
            'macd_histogram': float(indicators.get('macd', {}).get('histogram', 0) or 0),
            'bb_upper_rel': rel(indicators.get('bollinger_bands', {}).get('upper')),
            'bb_lower_rel': rel(indicators.get('bollinger_bands', {}).get('lower')),
            'bb_bandwidth': float(indicators.get('bollinger_bands', {}).get('bandwidth', 0) or 0),
            'atr_pct': float(indicators.get('atr_pct', 0) or 0),
            'support_rel': rel(indicators.get('support')),
            'resistance_rel': rel(indicators.get('resistance')),
            'vwap_rel': rel(indicators.get('vwap')),
            'price_change_pct': float(price_change_pct or 0),
            'volume_trend': float(volume_trend),
            'fvg_bullish': float(fvg_bullish),
            'fvg_bearish': float(fvg_bearish),
            'liquidity_sweep': sweep_map.get(liq_sweep, 0.0),
            'break_of_structure': bos_map.get(bos, 0.0),
        }

    def _predict_with_model(self, features: Dict[str, float]) -> Dict:
        """Run XGBoost model prediction."""
        try:
            feature_array = np.array([[features[f] for f in FEATURE_NAMES]])

            pred = self.model.predict(feature_array)[0]
            proba = self.model.predict_proba(feature_array)[0]

            if pred == 1:
                signal = 'LONG'
                confidence = int(proba[1] * 100)
            elif pred == -1:
                signal = 'SHORT'
                confidence = int(proba[0] * 100)
            else:
                signal = 'NEUTRAL'
                confidence = int(max(proba) * 100)

            confidence = max(50, min(95, confidence))

            return {'signal': signal, 'confidence': confidence}
        except Exception as e:
            logger.error(f"XGBoost prediction failed: {e}")
            return self._predict_rules_based(features)

    def _predict_rules_based(self, features: Dict[str, float]) -> Dict:
        """
        Rules-based fallback scoring system.
        Each indicator contributes +1 (bullish), -1 (bearish), or 0 (neutral).
        """
        score = 0
        factors = 0

        rsi = features['rsi_14']
        if rsi < 30:
            score += 1
        elif rsi > 70:
            score -= 1
        factors += 1

        ema9 = features['ema_9_rel']
        ema21 = features['ema_21_rel']
        ema50 = features['ema_50_rel']
        if ema9 > 0 and ema21 > 0 and ema50 > 0:
            score += 1
        elif ema9 < 0 and ema21 < 0 and ema50 < 0:
            score -= 1
        elif ema9 > ema21 > ema50:
            score += 0.5
        elif ema9 < ema21 < ema50:
            score -= 0.5
        factors += 1

        macd_hist = features['macd_histogram']
        if macd_hist > 0:
            score += 0.5
        elif macd_hist < 0:
            score -= 0.5
        factors += 1

        price = features['price_change_pct']
        if price > 2:
            score += 0.5
        elif price < -2:
            score -= 0.5
        factors += 1

        bb_upper = features['bb_upper_rel']
        bb_lower = features['bb_lower_rel']
        if bb_lower > 0:
            score += 1
        elif bb_upper < 0:
            score -= 1
        factors += 1

        atr = features['atr_pct']
        if atr < 0.15:
            factors += 0.5

        sweep = features['liquidity_sweep']
        if sweep > 0:
            score += 0.5
        elif sweep < 0:
            score -= 0.5
        factors += 1

        bos = features['break_of_structure']
        if bos > 0:
            score += 0.5
        elif bos < 0:
            score -= 0.5
        factors += 1

        vwap = features['vwap_rel']
        if vwap > 0:
            score += 0.3
        elif vwap < 0:
            score -= 0.3
        factors += 1

        vol = features['volume_trend']
        if vol > 0.2:
            score *= 1.1
        factors += 0.5

        normalized = score / max(factors, 1)

        if normalized > 0.3:
            signal = 'LONG'
            confidence = int(min(90, 55 + abs(normalized) * 60))
        elif normalized < -0.3:
            signal = 'SHORT'
            confidence = int(min(90, 55 + abs(normalized) * 60))
        else:
            signal = 'NEUTRAL'
            confidence = int(40 + abs(normalized) * 40)

        return {'signal': signal, 'confidence': confidence}


_global_xgb_model = None


def get_xgboost_model() -> XGBoostSignalModel:
    global _global_xgb_model
    if _global_xgb_model is None:
        _global_xgb_model = XGBoostSignalModel()
    return _global_xgb_model
