# services/signal_engine.py
import logging
import threading
import time
import math
import requests
from datetime import datetime, timedelta
from typing import Dict, Optional, List

from config import Config
from services.xgboost_model import get_xgboost_model
from services.groq_decision import get_decision_engine
from database.db_conn import execute_query, execute_query_all

logger = logging.getLogger(__name__)

SIGNAL_PAIRS = [
    'BTCUSDT', 'ETHUSDT',
    'BNBUSDT', 'SOLUSDT',
    'XRPUSDT', 'DOGEUSDT',
]

SIGNAL_TIMEFRAMES = ['15m', '1h']

SIGNAL_CYCLE_SECONDS = 300  # 5 minutes - one signal cycle every 5 minutes
SIGNAL_COOLDOWN_SECONDS = 300  # 5 minutes - global cooldown between signals

BINANCE_PUBLIC_URL = 'https://fapi.binance.com'


class TechnicalIndicators:
    @staticmethod
    def rsi(closes: List[float], period: int = 14) -> Optional[float]:
        if len(closes) < period + 1:
            return None
        gains = []
        losses = []
        for i in range(1, len(closes)):
            diff = closes[i] - closes[i - 1]
            gains.append(max(0, diff))
            losses.append(max(0, -diff))
        avg_gain = sum(gains[:period]) / period
        avg_loss = sum(losses[:period]) / period
        for i in range(period, len(gains)):
            avg_gain = (avg_gain * (period - 1) + gains[i]) / period
            avg_loss = (avg_loss * (period - 1) + losses[i]) / period
        if avg_loss == 0:
            return 100.0
        rs = avg_gain / avg_loss
        return 100 - (100 / (1 + rs))

    @staticmethod
    def ema(closes: List[float], period: int) -> Optional[float]:
        if len(closes) < period:
            return None
        multiplier = 2 / (period + 1)
        ema_val = sum(closes[:period]) / period
        for price in closes[period:]:
            ema_val = (price - ema_val) * multiplier + ema_val
        return ema_val

    @staticmethod
    def macd(closes: List[float]) -> Optional[Dict]:
        if len(closes) < 26:
            return None
        ema12 = TechnicalIndicators.ema(closes, 12)
        ema26 = TechnicalIndicators.ema(closes, 26)
        if ema12 is None or ema26 is None:
            return None
        macd_line = ema12 - ema26
        macd_values = []
        for i in range(26, len(closes) + 1):
            e12 = TechnicalIndicators.ema(closes[:i], 12)
            e26 = TechnicalIndicators.ema(closes[:i], 26)
            if e12 and e26:
                macd_values.append(e12 - e26)
        if len(macd_values) < 9:
            return {'macd_line': round(macd_line, 4), 'signal_line': None, 'histogram': None}
        signal_line = TechnicalIndicators.ema(macd_values, 9)
        histogram = macd_line - signal_line if signal_line else None
        return {
            'macd_line': round(macd_line, 4),
            'signal_line': round(signal_line, 4) if signal_line else None,
            'histogram': round(histogram, 4) if histogram else None,
        }

    @staticmethod
    def bollinger_bands(closes: List[float], period: int = 20, std_dev: float = 2.0) -> Optional[Dict]:
        if len(closes) < period:
            return None
        sma = sum(closes[-period:]) / period
        variance = sum((x - sma) ** 2 for x in closes[-period:]) / period
        std = math.sqrt(variance)
        return {
            'upper': round(sma + std_dev * std, 4),
            'middle': round(sma, 4),
            'lower': round(sma - std_dev * std, 4),
            'bandwidth': round((std_dev * std * 2) / sma * 100, 2) if sma > 0 else 0,
        }

    @staticmethod
    def atr(highs: List[float], lows: List[float], closes: List[float], period: int = 14) -> Optional[float]:
        if len(highs) < period + 1:
            return None
        true_ranges = []
        for i in range(1, len(highs)):
            tr = max(
                highs[i] - lows[i],
                abs(highs[i] - closes[i - 1]),
                abs(lows[i] - closes[i - 1])
            )
            true_ranges.append(tr)
        return sum(true_ranges[-period:]) / period

    @staticmethod
    def support_resistance(highs: List[float], lows: List[float], closes: List[float]) -> Dict:
        if len(closes) < 20:
            return {'support': 0, 'resistance': 0}
        recent_highs = highs[-20:]
        recent_lows = lows[-20:]
        return {
            'resistance': round(max(recent_highs), 4),
            'support': round(min(recent_lows), 4),
        }

    @staticmethod
    def vwap(highs: List[float], lows: List[float], closes: List[float], volumes: List[float]) -> Optional[float]:
        if len(closes) < 20 or not volumes:
            return None
        typical_prices = [(h + l + c) / 3 for h, l, c in zip(highs, lows, closes)]
        tpv = [tp * v for tp, v in zip(typical_prices, volumes)]
        return sum(tpv) / sum(volumes) if sum(volumes) > 0 else None

    @staticmethod
    def fair_value_gaps(closes: List[float], highs: List[float], lows: List[float]) -> List[Dict]:
        """Detect FVGs (Imbalances) in last 20 candles."""
        fvg_list = []
        for i in range(2, min(len(closes), 22)):
            # Bullish FVG: Candle 1 high < Candle 3 low
            if highs[i-2] < lows[i]:
                fvg_list.append({
                    'type': 'bullish',
                    'top': round(lows[i], 4),
                    'bottom': round(highs[i-2], 4),
                })
            # Bearish FVG: Candle 1 low > Candle 3 high
            elif lows[i-2] > highs[i]:
                fvg_list.append({
                    'type': 'bearish',
                    'top': round(lows[i-2], 4),
                    'bottom': round(highs[i], 4),
                })
        return fvg_list[-3:]  # Return last 3

    @staticmethod
    def liquidity_sweeps(highs: List[float], lows: List[float], closes: List[float]) -> Dict:
        """Detect recent liquidity sweeps (wicks taking out levels then reversing)."""
        if len(closes) < 10:
            return {'sweep': 'none'}
        recent_high = max(highs[-10:-1])
        recent_low = min(lows[-10:-1])
        last_candle = closes[-1]
        last_high = highs[-1]
        last_low = lows[-1]

        if last_high > recent_high and last_candle < recent_high:
            return {'sweep': 'bearish', 'level': round(recent_high, 4)}
        elif last_low < recent_low and last_candle > recent_low:
            return {'sweep': 'bullish', 'level': round(recent_low, 4)}
        return {'sweep': 'none'}

    @staticmethod
    def break_of_structure(highs: List[float], lows: List[float], closes: List[float]) -> str:
        """Detect Break of Structure (BOS)."""
        if len(closes) < 30:
            return 'none'
        prev_high = max(highs[-30:-10])
        prev_low = min(lows[-30:-10])
        last_close = closes[-1]

        if last_close > prev_high:
            return 'bullish_bos'
        elif last_close < prev_low:
            return 'bearish_bos'
        return 'none'


class SignalEngine:
    """
    Master signal bot - generates signals only when:
    1. No active trade for that symbol
    2. Cooldown period has passed since last signal
    3. Market conditions warrant a new signal
    """

    def __init__(self):
        self.running = False
        self._thread = None
        self.last_cycle_time = 0
        self._last_cycle_signals = 0
        self._symbol_last_signal = {}

    def start(self):
        if self.running:
            logger.warning("SignalEngine already running")
            return
        self.running = True
        self._thread = threading.Thread(target=self._run_loop, daemon=True, name="SignalEngine")
        self._thread.start()
        logger.info("SignalEngine started")

    def stop(self):
        self.running = False
        if self._thread:
            self._thread.join(timeout=10)
        logger.info("SignalEngine stopped")

    def _run_loop(self):
        try:
            while self.running:
                try:
                    self._cleanup_expired_signals()
                    self._generate_cycle()
                    self.last_cycle_time = time.time()
                    for _ in range(SIGNAL_CYCLE_SECONDS):
                        if not self.running:
                            break
                        time.sleep(1)
                except Exception as e:
                    logger.error(f"Signal cycle error: {e}")
                    time.sleep(10)
        except Exception as e:
            logger.critical(f"SignalEngine fatal error: {e}")

    def retrain_model(self):
        """Retrain XGBoost model in background using latest data."""
        try:
            from services.pretrain_xgboost import pretrain_model
            logger.info("Starting XGBoost model retraining...")
            success = pretrain_model()
            if success:
                from services.xgboost_model import get_xgboost_model, _global_xgb_model
                global _global_xgb_model
                _global_xgb_model = None
                logger.info("XGBoost model retrained and reloaded")
            else:
                logger.warning("Model retraining failed — continuing with existing model")
        except Exception as e:
            logger.error(f"Model retraining error: {e}")

    def _cleanup_expired_signals(self):
        try:
            result = execute_query(
                "DELETE FROM signals WHERE expires_at < NOW()",
                fetch_one=False
            )
            logger.info("Expired signals cleaned up")
        except Exception as e:
            logger.error(f"Failed to clean expired signals: {e}")

    def _get_klines(self, symbol: str, interval: str, limit: int = 200):
        try:
            url = f"{BINANCE_PUBLIC_URL}/fapi/v1/klines"
            params = {'symbol': symbol, 'interval': interval, 'limit': limit}
            resp = requests.get(url, params=params, timeout=10)
            resp.raise_for_status()
            data = resp.json()
            result = []
            for k in data:
                result.append({
                    'open_time': k[0],
                    'open': float(k[1]),
                    'high': float(k[2]),
                    'low': float(k[3]),
                    'close': float(k[4]),
                    'volume': float(k[5]),
                    'close_time': k[6],
                    'quote_volume': float(k[7]),
                    'trades': int(k[8]),
                })
            return result
        except Exception as e:
            logger.error(f"Failed to get klines for {symbol}: {e}")
            return None

    def _can_generate_signal(self, symbol: str) -> bool:
        if symbol in self._symbol_last_signal:
            elapsed = time.time() - self._symbol_last_signal[symbol]
            if elapsed < SIGNAL_COOLDOWN_SECONDS:
                return False
        return True

    def _get_recent_performance(self, symbol: str) -> str:
        """Get last 10 signal results for this symbol to feed back to AI."""
        try:
            results = execute_query_all(
                """SELECT t.status, t.profit_loss, s.signal, s.confidence, s.timeframe
                   FROM trades t
                   LEFT JOIN signals s ON (t.decision_details->>'signal_id')::int = s.id
                   WHERE t.symbol = %s AND t.status IN ('won', 'lost')
                   ORDER BY t.opened_at DESC
                   LIMIT 10""",
                (symbol,)
            )
            if not results:
                return "No recent trading history for this symbol"

            wins = sum(1 for r in results if r['status'] == 'won')
            losses = sum(1 for r in results if r['status'] == 'lost')
            total = wins + losses
            win_rate = (wins / total * 100) if total > 0 else 0

            lines = [f"Recent performance: {wins}W/{losses}L ({win_rate:.0f}% win rate)"]
            for r in results[:5]:
                pnl = float(r.get('profit_loss', 0) or 0)
                lines.append(f"  {r['signal']} | conf={r['confidence']}% | {'WON' if r['status'] == 'won' else 'LOST'} | PnL: ${pnl:.2f}")
            return "\n".join(lines)
        except Exception:
            return "No recent trading history available"

    def _generate_cycle(self):
        logger.info("Starting signal generation cycle...")

        # Check global cooldown - only one signal every 5 minutes
        if not self._can_generate_signal('GLOBAL'):
            logger.info(f"Global cooldown active, skipping this cycle")
            return

        # Rotate: pick all pairs every cycle
        current_pairs = SIGNAL_PAIRS
        logger.info(f"Analyzing pairs: {current_pairs}")

        global_best_symbol = None
        global_best_signal = None
        global_best_confidence = 0
        global_best_timeframe = None
        global_best_klines = None

        for symbol in current_pairs:
            recent_perf = self._get_recent_performance(symbol)

            tf_signals = {}
            for tf in SIGNAL_TIMEFRAMES:
                klines = self._get_klines(symbol, interval=tf, limit=200)
                if not klines or len(klines) < 50:
                    continue

                closes = [k['close'] for k in klines]
                highs = [k['high'] for k in klines]
                lows = [k['low'] for k in klines]
                volumes = [k['volume'] for k in klines]

                rsi = TechnicalIndicators.rsi(closes, 14)
                ema_9 = TechnicalIndicators.ema(closes, 9)
                ema_21 = TechnicalIndicators.ema(closes, 21)
                ema_50 = TechnicalIndicators.ema(closes, 50)
                macd = TechnicalIndicators.macd(closes)
                bb = TechnicalIndicators.bollinger_bands(closes, 20)
                atr = TechnicalIndicators.atr(highs, lows, closes, 14)
                sr = TechnicalIndicators.support_resistance(highs, lows, closes)
                vwap = TechnicalIndicators.vwap(highs, lows, closes, volumes)
                fvg = TechnicalIndicators.fair_value_gaps(closes, highs, lows)
                liq_sweep = TechnicalIndicators.liquidity_sweeps(highs, lows, closes)
                bos = TechnicalIndicators.break_of_structure(highs, lows, closes)

                current_price = closes[-1]
                price_change_20 = ((closes[-1] - closes[-20]) / closes[-20]) * 100 if len(closes) >= 20 else 0

                if atr and current_price > 0:
                    atr_pct = (atr / current_price) * 100
                    if atr_pct < 0.10:  # Lower threshold to allow more pairs
                        logger.debug(f"{symbol} [{tf}]: ATR too low ({atr_pct:.2f}%), skipping")
                        continue

                market_data = {
                    'current_price': current_price,
                    'price_history': closes[-50:],
                    'highs': highs[-50:],
                    'lows': lows[-50:],
                    'volumes': volumes[-50:],
                    'symbol': symbol,
                    'price_change_percent': round(price_change_20, 2),
                    'timeframe': tf,
                    'indicators': {
                        'rsi_14': round(rsi, 2) if rsi else None,
                        'ema_9': round(ema_9, 4) if ema_9 else None,
                        'ema_21': round(ema_21, 4) if ema_21 else None,
                        'ema_50': round(ema_50, 4) if ema_50 else None,
                        'macd': macd,
                        'bollinger_bands': bb,
                        'atr_14': round(atr, 4) if atr else None,
                        'atr_pct': round(atr_pct, 2) if atr else None,
                        'support': sr['support'],
                        'resistance': sr['resistance'],
                        'vwap': round(vwap, 4) if vwap else None,
                        'fair_value_gaps': fvg,
                        'liquidity_sweep': liq_sweep,
                        'break_of_structure': bos,
                    },
                    'recent_performance': recent_perf,
                }

                indicators = market_data['indicators']
                xgb_result = get_xgboost_model().predict(
                    indicators=indicators,
                    current_price=current_price,
                    price_change_pct=price_change_20,
                    volumes=volumes[-50:],
                )

                signal = xgb_result['signal']
                confidence = xgb_result['confidence']

                if signal in ['LONG', 'SHORT']:
                    reasoning = f"XGBoost {signal} {confidence}%"

                    tf_signals[tf] = {
                        'signal': signal,
                        'confidence': confidence,
                        'decision': {'signal': signal, 'confidence': confidence, 'reasoning': reasoning, 'entry_price': current_price},
                        'klines': klines,
                        'indicators': indicators,
                        'price_change_pct': price_change_20,
                    }

            if not tf_signals:
                continue

            best_tf = max(tf_signals.keys(), key=lambda t: tf_signals[t]['confidence'])
            best_entry = tf_signals[best_tf]

            # Multi-timeframe confirmation: at least 1 timeframe (relaxed for more signals)
            agreeing_tfs = [t for t, s in tf_signals.items() if s['signal'] == best_entry['signal']]
            if len(agreeing_tfs) < 1:
                logger.debug(f"{symbol}: No multi-TF confirmation for {best_entry['signal']}, skipping")
                continue

            boosted_confidence = min(95, best_entry['confidence'] + (len(agreeing_tfs) - 1) * 5)

            if boosted_confidence > global_best_confidence:
                global_best_confidence = boosted_confidence
                global_best_signal = best_entry['decision']
                global_best_timeframe = best_tf
                global_best_klines = best_entry['klines']
                global_best_symbol = symbol
                global_best_indicators = best_entry.get('indicators', {})
                global_best_price_change = best_entry.get('price_change_pct', 0)

        if global_best_signal and global_best_signal.get('signal') in ['LONG', 'SHORT'] and global_best_confidence >= 50:
            # ONE Groq validation per cycle — only on the final best signal
            ai_engine = get_decision_engine()
            rsi_val = float(global_best_indicators.get('rsi_14', 50) or 50)
            macd_hist = float(global_best_indicators.get('macd', {}).get('histogram', 0) or 0)
            ema9 = float(global_best_indicators.get('ema_9', 0) or 0)
            ema21 = float(global_best_indicators.get('ema_21', 0) or 0)
            ema50 = float(global_best_indicators.get('ema_50', 0) or 0)
            if ema9 > ema21 > ema50:
                ema_trend = 'bullish'
            elif ema9 < ema21 < ema50:
                ema_trend = 'bearish'
            else:
                ema_trend = 'mixed'

            ai_decision = ai_engine.validate_signal(
                xgb_signal=global_best_signal['signal'],
                xgb_confidence=global_best_confidence,
                symbol=global_best_symbol,
                current_price=global_best_signal.get('entry_price', 0),
                price_change_pct=global_best_price_change,
                rsi=rsi_val,
                macd_hist=macd_hist,
                ema_trend=ema_trend,
            )

            ai_signal = ai_decision.get('signal', 'NEUTRAL')
            ai_confidence = ai_decision.get('confidence', 0)
            reasoning = ai_decision.get('reasoning', f"XGBoost {global_best_signal['signal']} {global_best_confidence}%")

            if ai_signal == global_best_signal['signal']:
                global_best_confidence = min(95, int((global_best_confidence + ai_confidence) / 2))
                reasoning = f"XGB+AI agree: {global_best_signal['signal']} (XGB={global_best_confidence}%, AI={ai_confidence}%)"
            elif ai_signal != 'NEUTRAL':
                global_best_confidence = max(50, int(global_best_confidence * 0.7))
                reasoning = f"XGB {global_best_signal['signal']} {global_best_confidence}% (AI disagrees: {ai_signal})"
            else:
                reasoning = f"XGBoost {global_best_signal['signal']} {global_best_confidence}% (AI neutral)"

            global_best_signal['reasoning'] = reasoning

        if global_best_signal and global_best_signal.get('signal') in ['LONG', 'SHORT'] and global_best_confidence >= 50:
            entry_price = global_best_signal.get('entry_price', global_best_klines[-1]['close'] if global_best_klines else 0)
            atr_val = TechnicalIndicators.atr(
                [k['high'] for k in global_best_klines[-20:]],
                [k['low'] for k in global_best_klines[-20:]],
                [k['close'] for k in global_best_klines[-20:]],
                14
            )
            # Use fixed percentages: 2.5% SL, 3% TP
            sl_distance = entry_price * 0.025
            tp_distance = entry_price * 0.03

            if global_best_signal['signal'] == 'LONG':
                stop_loss = entry_price - sl_distance
                take_profit = entry_price + tp_distance
            else:
                stop_loss = entry_price + sl_distance
                take_profit = entry_price - tp_distance

            execute_query(
                """INSERT INTO signals (symbol, signal, confidence, entry_price, stop_loss, take_profit, timeframe, reasoning, expires_at)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP + INTERVAL '5 minutes')""",
                (
                    global_best_symbol,
                    global_best_signal['signal'],
                    global_best_confidence,
                    entry_price,
                    stop_loss,
                    take_profit,
                    global_best_timeframe,
                    global_best_signal.get('reasoning', '')
                )
            )

            # Update last signal time for GLOBAL cooldown (only one signal every 5 minutes)
            self._symbol_last_signal['GLOBAL'] = time.time()

            logger.info(f"SIGNAL: {global_best_signal['signal']} {global_best_symbol} on {global_best_timeframe} (conf={global_best_confidence}%)")
            logger.info("Next signal cycle in 5 minutes")
        else:
            logger.info(f"No signal met threshold this cycle (best confidence: {global_best_confidence}%)")

    def get_status(self) -> Dict:
        return {
            'running': self.running,
            'last_cycle_time': datetime.fromtimestamp(self.last_cycle_time).isoformat() if self.last_cycle_time else None,
            'last_cycle_signals': self._last_cycle_signals,
            'pairs': len(SIGNAL_PAIRS),
            'timeframes': len(SIGNAL_TIMEFRAMES),
        }


_global_signal_engine = None
_lock = threading.Lock()


def get_signal_engine() -> SignalEngine:
    global _global_signal_engine
    if _global_signal_engine is None:
        with _lock:
            if _global_signal_engine is None:
                _global_signal_engine = SignalEngine()
    return _global_signal_engine
