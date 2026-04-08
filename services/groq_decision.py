# =============================================================================
# BINANCE FUTURES TRADING BOT - Groq AI Decision Engine
# Version: 1.0
# Purpose: Integrate Groq AI for binary options trading signals
# Security: Rate limiting protects against API quota exhaustion
# Theme: Dark Red (#8b0000) + Light Sea Green (#20b2aa) only
# =============================================================================

import os
import sys
import time
import json
import hashlib
import threading
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, Tuple
from collections import defaultdict

# Third-party imports
from groq import Groq
from groq.types.chat import ChatCompletion

# Local imports
from config import Config
from utils.logger import log_audit_event

logger = logging.getLogger(__name__)


class RateLimiter:
    """
    Token bucket rate limiter for Groq API requests.
    Prevents exceeding API quotas and ensures fair usage.
    """

    def __init__(self, max_requests_per_minute: int = 60):
        self.max_requests = max_requests_per_minute
        self.tokens = max_requests_per_minute
        self.last_refill = time.time()
        self.refill_rate = max_requests_per_minute / 60.0  # tokens per second
        self.lock = threading.Lock()

    def acquire(self) -> bool:
        """
        Try to acquire a token. Returns True if successful, False if rate limited.
        """
        with self.lock:
            now = time.time()

            # Refill tokens based on elapsed time
            elapsed = now - self.last_refill
            self.tokens = min(
                self.max_requests,
                self.tokens + (elapsed * self.refill_rate)
            )
            self.last_refill = now

            # Check if we can acquire
            if self.tokens >= 1.0:
                self.tokens -= 1.0
                return True
            else:
                # Calculate wait time
                wait_time = (1.0 - self.tokens) / self.refill_rate
                logger.warning(f"Rate limited! Wait {wait_time:.2f}s before next request")
                return False

    def get_status(self) -> Dict[str, Any]:
        """Get current rate limiter status"""
        return {
            'tokens_remaining': self.tokens,
            'max_requests': self.max_requests,
            'is_limited': self.tokens < 1.0
        }


class TradingPromptFormatter:
    """
    Formats market data into optimized prompts for Groq AI.
    Context-aware prompting improves decision accuracy.
    """

    SYSTEM_PROMPT = """You are a professional crypto futures trader specializing in Smart Money Concepts and day trading.

Your task is to analyze market data and predict short-term price direction.
Output ONLY valid JSON with no extra text.

DECISION RULES:
- "LONG": Price is likely to go UP based on confluence of factors
- "SHORT": Price is likely to go DOWN based on confluence of factors
- "NEUTRAL": Market is choppy, ranging, or indicators strongly conflict

ANALYSIS APPROACH:
1. Price action - are candles making higher highs (bullish) or lower lows (bearish)?
2. RSI (14) - oversold (<30) suggests reversal up, overbought (>70) suggests reversal down
3. MACD - positive histogram = bullish momentum, negative = bearish
4. EMA alignment - price above 9/21/50 EMA chain = bullish, below = bearish
5. Bollinger Bands - price near upper band = potential pullback, lower = potential bounce
6. ATR - higher volatility = stronger moves, low ATR = choppy/consolidation
7. Fair Value Gaps - price often returns to fill imbalances
8. Liquidity Sweeps - wicks beyond levels often signal reversal
9. Break of Structure - confirms trend continuation
10. VWAP - institutional reference, price above = bullish bias, below = bearish
11. Support/Resistance - key levels where price reacts

CONFIDENCE GUIDELINES:
- 70-80: Strong confluence (5+ indicators agree + SMC confirmation)
- 60-70: Good confluence (3-4 indicators agree)
- 55-60: Moderate confluence (2-3 indicators agree with SMC support)
- Below 55: Use NEUTRAL - not enough evidence

IMPORTANT:
- Only trade when you have clear directional bias with confluence
- Quality over quantity - better to skip a trade than take a bad one
- Use SMC concepts (FVG, liquidity sweeps, BOS) to confirm technical signals

ALWAYS OUTPUT IN THIS EXACT FORMAT:
{"signal": "LONG"|"SHORT"|"NEUTRAL", "confidence": 0-100, "entry_price": 0, "duration": 60, "reasoning": "Brief explanation"}"""

    USER_PROMPT_TEMPLATE = """Analyze the following crypto market data and predict the next price movement.

Timeframe: {timeframe}
Risk Level: {risk_percentage}%
Strategy: {strategy}

Market Data:
{market_data}

Based on the data above, should I go LONG (buy) or SHORT (sell)?
Give your signal, confidence level (0-100), the current price as entry_price, and a brief reasoning."""

    @classmethod
    def format_prompt(cls, market_data: Dict[str, Any],
                      timeframe: str,
                      risk_percentage: float = 1.0,
                      strategy: str = 'default') -> str:
        """
        Convert raw market data into optimized AI prompt.

        Args:
            market_data: Current market indicators and prices
            timeframe: Trading timeframe (M1, M5, H1, etc.)
            risk_percentage: User's risk tolerance
            strategy: Trading strategy type

        Returns:
            Formatted prompt string for Groq API
        """
        # Extract key indicators from market data
        recent_perf = market_data.get('recent_performance', '')
        technical = cls._format_technical_indicators(market_data.get('indicators', {}))

        perf_section = f"\nRecent Performance:\n{recent_perf}" if recent_perf else ""

        prompt = cls.USER_PROMPT_TEMPLATE.format(
            timeframe=timeframe.upper(),
            risk_percentage=risk_percentage,
            strategy=strategy,
            market_data=cls._format_market_summary(market_data) + perf_section + "\n\n" + technical
        )

        return prompt

    @staticmethod
    def _format_market_summary(market_data: Dict[str, Any]) -> str:
        """Format market data as readable summary for AI"""
        lines = []

        if 'symbol' in market_data:
            lines.append(f"- Symbol: {market_data['symbol']}")

        if 'current_price' in market_data:
            lines.append(f"- Current Price: {market_data['current_price']:.2f}")

        if 'price_change_percent' in market_data:
            change = market_data['price_change_percent']
            lines.append(f"- Price Change (20 candles): {change:+.2f}%")

        if 'price_history' in market_data:
            history = market_data['price_history']
            if len(history) >= 2:
                changes = [history[i+1] - history[i] for i in range(len(history)-1)]
                up_candles = sum(1 for c in changes if c > 0)
                down_candles = sum(1 for c in changes if c < 0)
                total_move = history[-1] - history[0]
                direction = "UP" if total_move > 0 else "DOWN"
                momentum = "bullish" if up_candles > down_candles else "bearish"
                lines.append(f"- Last 20 Closes: {', '.join(f'{p:.2f}' for p in history)}")
                lines.append(f"- Net Change: {total_move:+.2f} ({direction})")
                lines.append(f"- Momentum: {momentum} ({up_candles} green, {down_candles} red)")

        if 'highs' in market_data and 'lows' in market_data:
            highs = market_data['highs']
            lows = market_data['lows']
            if highs and lows:
                lines.append(f"- 20c High: {max(highs):.2f}")
                lines.append(f"- 20c Low: {min(lows):.2f}")
                recent_high = max(highs[-5:])
                recent_low = min(lows[-5:])
                lines.append(f"- Recent 5c Range: {recent_low:.2f} - {recent_high:.2f}")

        if 'volumes' in market_data:
            volumes = market_data['volumes']
            if volumes:
                avg_vol = sum(volumes) / len(volumes)
                recent_vol = sum(volumes[-5:]) / 5
                vol_trend = "increasing" if recent_vol > avg_vol * 1.1 else "decreasing" if recent_vol < avg_vol * 0.9 else "stable"
                lines.append(f"- Volume Trend: {vol_trend} (recent avg: {recent_vol:.0f}, 20c avg: {avg_vol:.0f})")

        if 'indicators' in market_data and market_data['indicators']:
            lines.append(TradingPromptFormatter._format_technical_indicators(market_data['indicators']))

        if 'recent_trades' in market_data and market_data['recent_trades']:
            lines.append(TradingPromptFormatter._format_recent_performance(market_data['recent_trades']))

        return "\n".join(lines) if lines else "No market data available"

    @staticmethod
    def _format_technical_indicators(indicators: Dict[str, Any]) -> str:
        """Format technical indicators for AI context"""
        if not indicators:
            return "No technical indicators available"

        lines = []
        for name, value in indicators.items():
            if isinstance(value, dict):
                formatted = ', '.join(f'{k}={v}' for k, v in value.items() if v is not None)
                lines.append(f"- {name.replace('_', ' ').title()}: {formatted}")
            elif isinstance(value, (int, float)) and value is not None:
                lines.append(f"- {name.replace('_', ' ').title()}: {value:.4f}")
            elif value is not None:
                lines.append(f"- {name.replace('_', ' ').title()}: {value}")

        return "\n".join(lines)

    @staticmethod
    def _format_recent_performance(trades: list) -> str:
        """Format recent trading performance for context"""
        if not trades:
            return "No recent trading history"

        wins = sum(1 for t in trades if t.get('status') == 'won')
        losses = sum(1 for t in trades if t.get('status') == 'lost')
        total = len(trades)

        win_rate = (wins / total * 100) if total > 0 else 0
        pnl_total = sum(float(t.get('profit_loss', 0)) for t in trades[-10:])

        return f"- Last {total} trades: {wins} won, {losses} lost ({win_rate:.1f}% win rate)\n- Recent PnL: ${pnl_total:+.2f}"

    VALIDATION_PROMPT = """You are a crypto futures trader. XGBoost model already analyzed the market. Confirm or override.

XGBoost says: {xgb_signal} with {xgb_confidence}% confidence.
Market context: {context}

Reply ONLY with JSON:
{{"signal": "LONG"|"SHORT"|"NEUTRAL", "confidence": 0-100, "reasoning": "one sentence"}}"""

    @classmethod
    def format_validation_prompt(cls, xgb_signal: str, xgb_confidence: int,
                                  symbol: str, current_price: float,
                                  price_change_pct: float, rsi: float,
                                  macd_hist: float, ema_trend: str) -> str:
        """Tiny prompt for AI validation — ~50 tokens vs ~2000"""
        context = (
            f"{symbol} @ {current_price:.2f} ({price_change_pct:+.1f}% in 20c). "
            f"RSI={rsi:.0f}, MACD hist={macd_hist:+.2f}, EMA trend={ema_trend}."
        )
        return cls.VALIDATION_PROMPT.format(
            xgb_signal=xgb_signal,
            xgb_confidence=xgb_confidence,
            context=context,
        )


class GroqDecisionEngine:
    """
    Core Groq AI integration engine for trading decisions.
    Manages API connections, rate limiting, and response parsing.
    """

    def __init__(self, api_key: str = None, model: str = None):
        """
        Initialize Groq decision engine.

        Args:
            api_key: Groq API key (defaults to config)
            model: Groq model name (defaults to config)
        """
        self.api_key = api_key or Config.GROQ_API_KEY
        self.model = model or Config.GROQ_MODEL

        # Initialize client with proxy disabled (fixes Windows proxy error)
        import os
        os.environ.pop('HTTP_PROXY', None)
        os.environ.pop('HTTPS_PROXY', None)
        os.environ.pop('http_proxy', None)
        os.environ.pop('https_proxy', None)

        self.client = Groq(api_key=self.api_key, http_client=None)

        # Initialize rate limiter
        self.rate_limiter = RateLimiter(max_requests_per_minute=30)

        # Decision cache (prevents duplicate calls for same market state)
        self.decision_cache = {}
        self.cache_ttl_seconds = 120  # 2 minutes - reduces API calls significantly

        # Track failed requests
        self.failed_requests = 0
        self.successful_requests = 0
        self.lock = threading.Lock()

        # Backoff tracking per symbol
        self._backoff_until = {}  # symbol -> timestamp when we can retry

        logger.info("GroqDecisionEngine initialized")

    def make_trading_decision(self,
                              price_data: Dict[str, Any],
                              timeframe: str,
                              user_id: int,
                              strategy: str = 'default',
                              risk_percentage: float = 1.0) -> Dict[str, Any]:
        """
        Generate trading decision using Groq AI.

        Args:
            price_data: Current market data and indicators
            timeframe: Trading timeframe
            user_id: User ID for audit logging
            strategy: Strategy type for AI context
            risk_percentage: User's risk tolerance

        Returns:
            Dictionary with signal, confidence, entry_price, reasoning
        """
        try:
            # Check rate limit first
            if not self.rate_limiter.acquire():
                logger.warning(f"Rate limit exceeded for user {user_id}")
                # Return neutral signal instead of failing
                return {
                    'signal': 'NEUTRAL',
                    'confidence': 0,
                    'entry_price': price_data.get('current_price', 0),
                    'reasoning': 'Rate limited by API quotas'
                }

            # Check decision cache
            cache_key = self._generate_cache_key(price_data, timeframe, strategy)
            cached_decision = self._check_cache(cache_key)
            if cached_decision:
                logger.info(f"Returning cached decision for user {user_id}")
                self.successful_requests += 1
                return cached_decision

            # Format prompt for AI
            prompt = TradingPromptFormatter.format_prompt(
                market_data=price_data,
                timeframe=timeframe,
                risk_percentage=risk_percentage,
                strategy=strategy
            )

            # Call Groq API
            start_time = time.time()
            response = self._call_groq_api(prompt)
            call_duration = time.time() - start_time

            # Parse response
            decision = self._parse_ai_response(response, price_data.get('current_price', 0))

            # Update cache
            self._update_cache(cache_key, decision)

            # Log success metrics
            with self.lock:
                self.successful_requests += 1

            # Log audit event
            log_audit_event(
                user_id=user_id,
                event_type='AI_DECISION_MADE',
                details={
                    'timeframe': timeframe,
                    'strategy': strategy,
                    'signal': decision.get('signal'),
                    'confidence': decision.get('confidence'),
                    'api_call_duration_seconds': round(call_duration, 3)
                }
            )

            logger.info(f"Ai decision made: {decision}")
            return decision

        except Exception as e:
            logger.error(f"Groq AI decision failed: {str(e)}")

            with self.lock:
                self.failed_requests += 1

            # Log failure event
            log_audit_event(
                user_id=user_id,
                event_type='AI_DECISION_FAILED',
                details={
                    'error': str(e),
                    'timeframe': timeframe,
                    'strategy': strategy
                }
            )

            # Return neutral signal on error (fail safe)
            return {
                'signal': 'NEUTRAL',
                'confidence': 0,
                'entry_price': price_data.get('current_price', 0),
                'reasoning': f'AI error: {str(e)[:100]}'
            }

    def _call_groq_api(self, prompt: str) -> Dict[str, Any]:
        """
        Execute actual Groq API call.

        Args:
            prompt: Formatted trading analysis prompt

        Returns:
            Raw API response
        """
        try:
            chat_completion = self.client.chat.completions.create(
                messages=[
                    {
                        "role": "system",
                        "content": TradingPromptFormatter.SYSTEM_PROMPT
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                model=self.model,
                temperature=0.7,
                max_tokens=400,
                top_p=1,
                stop=None,
                stream=False
            )

            return chat_completion.choices[0].message.content

        except Exception as e:
            logger.error(f"Groq API call failed: {str(e)}")
            raise

    def _parse_ai_response(self, response: str, current_price: float) -> Dict[str, Any]:
        """
        Parse AI response into structured decision object.
        Implements robust JSON extraction and validation.

        Args:
            response: Raw AI response string
            current_price: Current market price for fallback

        Returns:
            Validated decision dictionary
        """
        try:
            # Clean response - extract JSON block if present
            cleaned_response = self._extract_json_from_response(response)

            # Parse JSON
            decision = json.loads(cleaned_response)

            # Validate required fields
            if not isinstance(decision, dict):
                raise ValueError("Response must be JSON object")

            signal = decision.get('signal', 'NEUTRAL').upper()
            if signal not in ['LONG', 'SHORT', 'NEUTRAL']:
                signal = 'NEUTRAL'

            confidence = decision.get('confidence', 0)
            if not isinstance(confidence, (int, float)):
                confidence = 0
            confidence = max(0, min(100, confidence))  # Clamp 0-100

            entry_price = decision.get('entry_price', current_price)
            if not isinstance(entry_price, (int, float)):
                entry_price = current_price

            duration = decision.get('duration', 60)
            if not isinstance(duration, (int, float)):
                duration = 60
            duration = max(15, min(300, int(duration)))  # Clamp 15s-5min

            reasoning = decision.get('reasoning', 'No reasoning provided')
            if not isinstance(reasoning, str):
                reasoning = str(reasoning)

            return {
                'signal': signal,
                'confidence': confidence,
                'entry_price': float(entry_price),
                'duration': duration,
                'reasoning': reasoning
            }

        except json.JSONDecodeError as e:
            logger.error(f"JSON decode error: {str(e)}")
            logger.error(f"Raw response was: {response[:500]}...")
            raise
        except Exception as e:
            logger.error(f"Decision parsing error: {str(e)}")
            raise

    def _extract_json_from_response(self, response: str) -> str:
        """
        Extract JSON from potentially noisy AI response.
        Handles cases where AI includes markdown formatting or explanations.
        """
        # Try to find JSON block between ```json markers
        start_idx = response.find('```json')
        end_idx = response.find('```', start_idx + 7)

        if start_idx != -1 and end_idx != -1:
            response = response[start_idx + 7:end_idx].strip()
        else:
            # Try to find JSON braces
            start_idx = response.find('{')
            end_idx = response.rfind('}')

            if start_idx != -1 and end_idx != -1:
                response = response[start_idx:end_idx + 1]

        return response

    def _generate_cache_key(self, price_data: Dict[str, Any],
                            timeframe: str,
                            strategy: str) -> str:
        """
        Generate unique cache key based on market state.
        Ensures cache doesn't expire due to minor price variations.
        """
        # Use rounded price and key indicators for consistent caching
        base_price = round(price_data.get('current_price', 0), 4)
        volume = price_data.get('volume', 0)

        cache_string = f"{base_price}_{volume}_{timeframe}_{strategy}"

        # Generate hash
        return hashlib.md5(cache_string.encode()).hexdigest()

    def _check_cache(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """
        Check if decision exists in cache and is still valid.
        """
        if cache_key not in self.decision_cache:
            return None

        entry = self.decision_cache[cache_key]

        # Check TTL expiry
        if time.time() - entry['timestamp'] > self.cache_ttl_seconds:
            del self.decision_cache[cache_key]
            return None

        return entry['data']

    def _update_cache(self, cache_key: str, decision: Dict[str, Any]):
        """Update decision cache with new result"""
        self.decision_cache[cache_key] = {
            'data': decision,
            'timestamp': time.time()
        }

    def clear_cache(self):
        """Clear all cached decisions"""
        self.decision_cache.clear()
        logger.info("Groq decision cache cleared")

    def get_metrics(self) -> Dict[str, Any]:
        """Get current engine metrics"""
        return {
            'rate_limiter_status': self.rate_limiter.get_status(),
            'cache_entries': len(self.decision_cache),
            'successful_requests': self.successful_requests,
            'failed_requests': self.failed_requests,
            'success_rate': round(
                (self.successful_requests / (self.successful_requests + self.failed_requests) * 100)
                if (self.successful_requests + self.failed_requests) > 0 else 0, 2
            ),
            'model_used': self.model
        }


    def validate_signal(self, xgb_signal: str, xgb_confidence: int,
                        symbol: str, current_price: float,
                        price_change_pct: float, rsi: float,
                        macd_hist: float, ema_trend: str) -> Dict[str, Any]:
        """Lightweight AI validation — ~50 tokens vs ~2000"""
        try:
            if not self.rate_limiter.acquire():
                return {'signal': xgb_signal, 'confidence': xgb_confidence, 'reasoning': 'AI rate limited'}

            prompt = TradingPromptFormatter.format_validation_prompt(
                xgb_signal, xgb_confidence, symbol, current_price,
                price_change_pct, rsi, macd_hist, ema_trend,
            )

            response = self._call_groq_api(prompt)
            decision = self._parse_ai_response(response, current_price)
            self.successful_requests += 1
            return decision
        except Exception as e:
            logger.error(f"AI validation failed: {e}")
            self.failed_requests += 1
            return {'signal': xgb_signal, 'confidence': xgb_confidence, 'reasoning': f'AI error: {str(e)[:80]}'}


# Global instance for easy access across services
_global_engine = None
_engine_lock = threading.Lock()


def get_decision_engine() -> GroqDecisionEngine:
    """Singleton pattern for GroqDecisionEngine instance"""
    global _global_engine

    if _global_engine is None:
        with _engine_lock:
            if _global_engine is None:
                _global_engine = GroqDecisionEngine()

    return _global_engine


def reset_engine():
    """Reset global engine instance (for testing)"""
    global _global_engine
    _global_engine = None
    logger.info("Groq decision engine reset")


# Public API function for use in bot_engine.py
def make_trading_decision(price_data: Dict[str, Any],
                          timeframe: str,
                          user_id: int,
                          strategy: str = 'default',
                          risk_percentage: float = 1.0) -> Dict[str, Any]:
    """
    Convenience function for calling Groq decision engine.
    Matches bot_engine.py import signature exactly.

    Args:
        price_data: Market data dictionary
        timeframe: Trading timeframe
        user_id: User ID for audit logging
        strategy: Strategy type
        risk_percentage: User risk tolerance

    Returns:
        Decision dictionary with signal, confidence, entry_price, reasoning
    """
    engine = get_decision_engine()
    return engine.make_trading_decision(
        price_data=price_data,
        timeframe=timeframe,
        user_id=user_id,
        strategy=strategy,
        risk_percentage=risk_percentage
    )


__all__ = [
    'GroqDecisionEngine',
    'TradingPromptFormatter',
    'RateLimiter',
    'get_decision_engine',
    'reset_engine',
    'make_trading_decision'
]