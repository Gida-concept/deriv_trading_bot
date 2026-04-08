# services/bot_engine.py
import asyncio
import json
import logging
from datetime import datetime
from typing import Dict, Optional

from config import Config
from services.binance_futures import BinanceFuturesClient
from services.timeframe_lock import check_and_acquire_timeframe_lock
from utils.logger import log_audit_event
from database.db_conn import execute_query, execute_query_all

logger = logging.getLogger(__name__)

_bot_instances = {}


def get_or_create_bot(user_id: int, timeframe: str, strategy: str = 'default') -> Optional['BotEngine']:
    key = f"{user_id}_{timeframe}"
    if key not in _bot_instances:
        bot = BotEngine(user_id=user_id, timeframe=timeframe, strategy=strategy)
        _bot_instances[key] = bot
    return _bot_instances[key]


def remove_bot(user_id: int, timeframe: str):
    key = f"{user_id}_{timeframe}"
    if key in _bot_instances:
        _bot_instances[key].running = False
        del _bot_instances[key]


class BotEngine:
    """
    User trading bot - reads signals from the shared signals table
    and executes trades using the user's Binance API credentials.
    No Groq calls here - signals come from the master SignalEngine.
    """

    MONITORED_PAIRS = [
        'BTCUSDT', 'ETHUSDT', 'BNBUSDT', 'SOLUSDT', 'XRPUSDT', 'DOGEUSDT',
    ]

    def __init__(self, user_id: int, timeframe: str = '15m', strategy: str = 'default'):
        self.user_id = user_id
        self.timeframe = timeframe
        self.strategy = strategy
        self.running = False
        self.client = None
        self.session_id = None
        self.demo_live_mode = 'demo'
        self.stake_amount = 10.0
        self.risk_percentage = 5.0
        self.leverage = 10
        self.take_profit_percent = 3.0
        self.stop_loss_percent = 2.5
        self.max_concurrent_positions = 1
        self.trades_executed = 0
        self.wins = 0
        self.losses = 0
        self.consecutive_losses = 0
        self.net_pnl = 0.0
        self._active_symbols = set()
        self._processed_signal_ids = set()
        self._retrain_triggered = False

        logger.info(f"BotEngine initialized for user {user_id} (signal follower)")

    async def run(self):
        self.running = True

        try:
            await self._load_session_settings()

            if not await self._validate_credentials():
                logger.error("No valid Binance credentials")
                await self._update_session_status('error', 'No valid API credentials')
                return

            if not await self._establish_connection():
                logger.error("Failed to connect to Binance Futures")
                await self._update_session_status('error', 'Connection failed')
                return

            logger.info(f"BotEngine started for user {self.user_id} - following shared signals")

            while self.running:
                try:
                    await self._check_and_execute_signals()
                    await self._manage_positions()

                    if self._retrain_triggered:
                        from services.signal_engine import get_signal_engine
                        get_signal_engine().retrain_model()
                        self._retrain_triggered = False

                    await self.async_sleep(30)

                except KeyboardInterrupt:
                    logger.info("KeyboardInterrupt received, stopping bot")
                    break
                except Exception as e:
                    logger.error(f"Error in bot loop: {str(e)}")
                    await self.async_sleep(10)

        except Exception as e:
            logger.critical(f"BotEngine fatal error: {str(e)}")
            await self._update_session_status('error', error_message=str(e))
        finally:
            await self.shutdown()

    async def async_sleep(self, seconds: int):
        await asyncio.sleep(seconds)

    async def _load_session_settings(self):
        try:
            result = execute_query(
                """SELECT id, demo_live, current_stake, risk_percentage 
                   FROM bot_sessions 
                   WHERE user_id = %s AND timeframe = %s 
                   ORDER BY started_at DESC LIMIT 1""",
                (self.user_id, self.timeframe),
                fetch_one=True
            )
            if result:
                self.session_id = result['id']
                self.demo_live_mode = result.get('demo_live', 'demo')
                self.stake_amount = float(result.get('current_stake', 10.0))
                self.risk_percentage = float(result.get('risk_percentage', 5.0))
                logger.info(f"Loaded session: stake={self.stake_amount} USDT, risk={self.risk_percentage}%")
        except Exception as e:
            logger.error(f"Failed to load session settings: {e}")

    async def _sync_active_positions(self):
        """Sync in-memory active positions with actual exchange positions on startup."""
        try:
            positions = self.client.get_all_positions()
            for pos in positions:
                self._active_symbols.add(pos['symbol'])
            if self._active_symbols:
                logger.info(f"Synced active positions from exchange: {self._active_symbols}")
            else:
                logger.info("No active positions on exchange")
        except Exception as e:
            logger.error(f"Failed to sync active positions: {e}")

    async def _validate_credentials(self) -> bool:
        try:
            result = execute_query(
                """SELECT api_key_encrypted, api_secret_encrypted 
                   FROM user_api_keys WHERE user_id = %s AND is_active = TRUE LIMIT 1""",
                (self.user_id,),
                fetch_one=True
            )
            return result is not None and result.get('api_key_encrypted')
        except Exception as e:
            logger.error(f"Credential validation failed: {e}")
            return False

    async def _establish_connection(self) -> bool:
        try:
            result = execute_query(
                """SELECT api_key_encrypted, api_secret_encrypted 
                   FROM user_api_keys WHERE user_id = %s AND is_active = TRUE LIMIT 1""",
                (self.user_id,),
                fetch_one=True
            )

            if not result:
                logger.error("No Binance credentials found")
                return False

            api_key = self._decrypt_credentials(result['api_key_encrypted'])
            api_secret = self._decrypt_credentials(result['api_secret_encrypted'])

            if not api_key or not api_secret:
                logger.error("Failed to decrypt Binance credentials")
                return False

            self.client = BinanceFuturesClient(
                api_key=api_key,
                api_secret=api_secret,
                testnet=(self.demo_live_mode == 'demo')
            )

            if self.client.connect():
                await self._update_session_status('active')
                await self._sync_active_positions()
                return True
            return False

        except Exception as e:
            logger.error(f"Connection failed: {e}")
            return False

    def _decrypt_credentials(self, encrypted_value: str) -> str:
        try:
            from utils.encryptor import decrypt_api_key
            return decrypt_api_key(encrypted_value)
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            return ""

    async def _check_and_execute_signals(self):
        """Read latest signals from DB and execute trades for matching symbols."""
        try:
            signals = execute_query(
                """SELECT id, symbol, signal, confidence, entry_price, stop_loss, take_profit, timeframe, reasoning, created_at
                   FROM signals
                   WHERE signal IN ('LONG', 'SHORT')
                     AND expires_at > NOW()
                     AND symbol = ANY(%s)
                     AND timeframe = %s
                   ORDER BY created_at DESC
                   LIMIT 5""",
                (self.MONITORED_PAIRS, self.timeframe),
                fetch_all=True
            )

            logger.info(f"Checking for signals, found {len(signals)} signals")

            if not signals:
                if self._active_symbols:
                    logger.info("No valid signals — closing all open positions")
                    for active_symbol in list(self._active_symbols):
                        result = self.client.close_position(active_symbol)
                        pnl = result['realized_pnl'] if result else 0
                        pnl_pct = self._calculate_pnl_percent(active_symbol, pnl)

                        if pnl > 0:
                            self.wins += 1
                            self.net_pnl += pnl
                            status = 'won'
                        else:
                            self.losses += 1
                            status = 'lost'

                        self._active_symbols.discard(active_symbol)
                        self._update_trade_status(active_symbol, status, pnl, pnl_pct)
                return

            for sig in signals:
                if not self.running:
                    break

                if sig['id'] in self._processed_signal_ids:
                    continue

                symbol = sig['symbol']

                confidence = sig['confidence']
                if confidence < 50:  # Lowered threshold to match signal engine
                    logger.info(f"{symbol}: Signal confidence too low ({confidence}%), skipping")
                    self._processed_signal_ids.add(sig['id'])
                    continue

                # If we have an active position, close it and take the new signal
                if self._active_symbols:
                    for active_symbol in list(self._active_symbols):
                        logger.info(f"Closing existing position {active_symbol} for new signal on {symbol}")
                        result = self.client.close_position(active_symbol)
                        pnl = result['realized_pnl'] if result else 0
                        pnl_pct = self._calculate_pnl_percent(active_symbol, pnl)

                        if pnl > 0:
                            self.wins += 1
                            self.net_pnl += pnl
                            status = 'won'
                        else:
                            self.losses += 1
                            status = 'lost'

                        self._active_symbols.discard(active_symbol)
                        self._update_trade_status(active_symbol, status, pnl, pnl_pct)

                await self._execute_signal(sig)

        except Exception as e:
            logger.error(f"Failed to check signals: {e}")

    async def _execute_signal(self, signal: Dict):
        """Execute a trade based on a shared signal."""
        try:
            symbol = signal['symbol']
            side = signal['signal']
            entry_price = float(signal['entry_price'])
            stop_loss = float(signal['stop_loss'])
            take_profit = float(signal['take_profit'])
            sig_timeframe = signal.get('timeframe', self.timeframe)

            logger.info(f"Following signal: {side} {symbol} on {sig_timeframe} (conf={signal['confidence']}%)")

            # Get account balance and calculate 5% of it for stake
            account_balance = self.client.get_account_balance()
            if account_balance > 0:
                # Use 5% of account balance as stake amount
                calculated_stake = account_balance * 0.05
                logger.info(f"Account balance: {account_balance} USDT, Using 5%: {calculated_stake} USDT")
                stake_to_use = calculated_stake
            else:
                # Fallback to configured stake_amount if balance fetch fails
                stake_to_use = self.stake_amount
                logger.warning(f"Could not get account balance, using default stake: {stake_to_use} USDT")

            quantity = self.client.calculate_quantity(symbol, stake_to_use, self.leverage)
            if quantity <= 0:
                logger.warning(f"{symbol}: Invalid quantity calculated (stake={stake_to_use}, leverage={self.leverage})")
                self._processed_signal_ids.add(signal['id'])
                return

            result = self.client.open_position(
                symbol=symbol,
                side=side,
                quantity=quantity,
                leverage=self.leverage,
                stop_loss=stop_loss,
                take_profit=take_profit
            )

            if result and isinstance(result, dict) and result.get('order_id'):
                self._active_symbols.add(symbol)
                self.trades_executed += 1
                self._save_trade_record(symbol, side, quantity, entry_price, stop_loss, take_profit, signal)
                logger.info(f"Opened {side} {symbol} on {sig_timeframe}: qty={quantity}, SL={stop_loss}, TP={take_profit}")

                log_audit_event(
                    user_id=self.user_id,
                    event_type='SIGNAL_TRADE_EXECUTED',
                    details={
                        'symbol': symbol,
                        'signal': side,
                        'confidence': signal['confidence'],
                        'timeframe': sig_timeframe,
                        'entry_price': entry_price,
                    }
                )
            else:
                logger.error(f"{symbol}: open_position returned None — trade NOT opened")

        except Exception as e:
            logger.error(f"Failed to execute signal for {symbol}: {e}")
        finally:
            self._processed_signal_ids.add(signal['id'])

    async def _manage_positions(self):
        try:
            positions = self.client.get_all_positions()
            active_symbols_on_exchange = {pos['symbol'] for pos in positions}

            for pos in positions:
                symbol = pos['symbol']
                pnl_percent = 0
                if pos['entry_price'] > 0:
                    if pos['side'] == 'LONG':
                        pnl_percent = ((pos['unrealized_pnl'] / (pos['entry_price'] * pos['size'])) * 100)
                    else:
                        pnl_percent = ((-pos['unrealized_pnl'] / (pos['entry_price'] * pos['size'])) * 100)

                logger.info(f"{symbol}: {pos['side']} | Entry: {pos['entry_price']} | PnL: {pos['unrealized_pnl']:.2f} USDT ({pnl_percent:.1f}%)")

            # Detect positions closed by exchange (SL/TP hit or manual close)
            for symbol in list(self._active_symbols):
                if symbol not in active_symbols_on_exchange:
                    pnl = self._get_closed_trade_pnl(symbol)

                    if pnl > 0:
                        self.wins += 1
                        self.net_pnl += pnl
                        status = 'won'
                    else:
                        self.losses += 1
                        status = 'lost'

                    pnl_pct = self._calculate_pnl_percent(symbol, pnl)
                    logger.info(f"{symbol}: Position closed by exchange — {status} (PnL: {pnl:.2f} USDT, {pnl_pct:.1f}%)")
                    self._active_symbols.discard(symbol)
                    self._update_trade_status(symbol, status, pnl, pnl_pct)

        except Exception as e:
            logger.error(f"Position management failed: {e}")

    def _get_closed_trade_pnl(self, symbol: str) -> float:
        """Get realized PnL for a closed trade from Binance income history."""
        try:
            import time
            end_time = int(time.time() * 1000)
            start_time = end_time - (10 * 60 * 1000)

            income = self.client.futures_income_history(
                symbol=symbol,
                startTime=start_time,
                endTime=end_time,
                limit=100
            )

            total_pnl = 0.0
            for record in income:
                income_type = record.get('incomeType', '')
                if income_type in ('REALIZED_PNL', 'COMMISSION'):
                    total_pnl += float(record.get('income', 0))

            return total_pnl
        except Exception as e:
            logger.error(f"Failed to get closed trade PnL for {symbol}: {e}")
            return 0.0

    def _calculate_pnl_percent(self, symbol: str, pnl: float) -> float:
        """Calculate PnL percentage based on stake and leverage."""
        if self.stake_amount <= 0:
            return 0.0
        return (pnl / (self.stake_amount * self.leverage)) * 100

    def _save_trade_record(self, symbol: str, side: str, quantity: float,
                           entry_price: float, stop_loss: float, take_profit: float,
                           signal: Dict):
        try:
            execute_query(
                """INSERT INTO trades 
                   (user_id, bot_session_id, symbol, contract_type, entry_price, 
                    stake_amount, duration_seconds, timeframe, status, opened_at, decision_details)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                (
                    self.user_id, self.session_id, symbol, side,
                    entry_price, self.stake_amount, 0, signal.get('timeframe', self.timeframe),
                    'open', datetime.utcnow(),
                    json.dumps({
                        'signal_id': signal['id'],
                        'confidence': signal['confidence'],
                        'reasoning': signal.get('reasoning', ''),
                        'source': 'shared_signal',
                    })
                )
            )
        except Exception as e:
            logger.error(f"Failed to save trade record: {e}")

    def _update_trade_status(self, symbol: str, status: str, pnl: float, pnl_percent: float = 0.0):
        try:
            execute_query(
                """UPDATE trades SET status = %s, profit_loss = %s, profit_loss_pct = %s, closed_at = %s
                   WHERE id = (
                       SELECT id FROM trades
                       WHERE user_id = %s AND symbol = %s AND status = 'open'
                       ORDER BY opened_at DESC LIMIT 1
                   )""",
                (status, pnl, pnl_percent, datetime.utcnow(), self.user_id, symbol)
            )

            if status == 'won':
                self.consecutive_losses = 0
            elif status == 'lost':
                self.consecutive_losses += 1

            total_trades = self.wins + self.losses
            if total_trades > 0 and total_trades % 50 == 0 and not self._retrain_triggered:
                logger.info(f"Reached {total_trades} trades — triggering model retrain")
                self._retrain_triggered = True
            elif self.consecutive_losses >= 5 and not self._retrain_triggered:
                logger.warning(f"5 consecutive losses — triggering model retrain")
                self._retrain_triggered = True
            elif self._retrain_triggered and total_trades % 50 != 0 and self.consecutive_losses < 5:
                self._retrain_triggered = False

        except Exception as e:
            logger.error(f"Failed to update trade status: {e}")

    async def _update_session_status(self, status: str, error_message: str = None):
        try:
            if self.session_id:
                execute_query(
                    """UPDATE bot_sessions SET bot_state = %s, stopped_at = %s
                       WHERE id = %s""",
                    (status if error_message else 'active', datetime.utcnow(), self.session_id)
                )
        except Exception as e:
            logger.error(f"Failed to update session status: {e}")

    async def shutdown(self):
        self.running = False
        if self.client:
            self.client.disconnect()
        await self._update_session_status('stopped')
        logger.info(f"BotEngine shut down for user {self.user_id}")
