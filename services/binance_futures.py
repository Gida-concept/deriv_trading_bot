# services/binance_futures.py
import logging
import time
from typing import Optional, Dict, List
from binance.client import Client
from binance.exceptions import BinanceAPIException
from config import Config

logger = logging.getLogger(__name__)


class BinanceFuturesClient:
    """
    Binance USDT-M Futures trading client.
    Supports multi-pair trading with SL/TP management.
    """

    # Default trading pairs (top volume + volatility)
    DEFAULT_PAIRS = [
        'BTCUSDT', 'ETHUSDT', 'BNBUSDT', 'SOLUSDT', 'XRPUSDT', 'DOGEUSDT',
        'ADAUSDT', 'AVAXUSDT', 'LINKUSDT', 'DOTUSDT', 'MATICUSDT', 'SHIBUSDT',
        'LTCUSDT', 'UNIUSDT', 'ATOMUSDT', 'ETCUSDT', 'NEARUSDT', 'FILUSDT',
        'APTUSDT', 'ARBUSDT'
    ]

    def __init__(self, api_key: str, api_secret: str, testnet: bool = True):
        self.api_key = api_key
        self.api_secret = api_secret
        self.testnet = testnet
        self.client = None
        self.connected = False
        self._positions = {}

    def connect(self) -> bool:
        """Initialize Binance Futures client."""
        try:
            if self.testnet:
                self.client = Client(self.api_key, self.api_secret, testnet=True)
            else:
                self.client = Client(self.api_key, self.api_secret)

            # Verify connection
            account = self.client.futures_account()
            self.connected = True
            balance = account.get('totalWalletBalance', 0)
            logger.info(f"Binance Futures connected (testnet={self.testnet})")
            logger.info(f"Account balance: {balance} USDT")
            return True

        except BinanceAPIException as e:
            logger.error(f"Binance API error: {e}")
            return False
        except Exception as e:
            logger.error(f"Connection failed: {e}")
            return False

    def disconnect(self):
        """Close connection."""
        self.client = None
        self.connected = False
        self._positions.clear()
        logger.info("Binance Futures disconnected")

    def get_account_balance(self) -> float:
        """Get total USDT wallet balance."""
        try:
            account = self.client.futures_account()
            return float(account.get('totalWalletBalance', 0))
        except Exception as e:
            logger.error(f"Failed to get balance: {e}")
            return 0.0

    def get_klines(self, symbol: str, interval: str = '15m', limit: int = 100) -> Optional[List[Dict]]:
        """
        Get kline (candlestick) data for technical analysis.
        """
        try:
            klines = self.client.futures_klines(symbol=symbol, interval=interval, limit=limit)
            result = []
            for k in klines:
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

    def get_current_price(self, symbol: str) -> Optional[float]:
        """Get current mark price for a symbol."""
        try:
            ticker = self.client.futures_mark_price(symbol=symbol)
            return float(ticker['markPrice'])
        except Exception as e:
            logger.error(f"Failed to get price for {symbol}: {e}")
            return None

    def get_position(self, symbol: str) -> Optional[Dict]:
        """Get current position info for a symbol."""
        try:
            positions = self.client.futures_position_information(symbol=symbol)
            for pos in positions:
                if float(pos['positionAmt']) != 0:
                    return {
                        'symbol': pos['symbol'],
                        'side': 'LONG' if float(pos['positionAmt']) > 0 else 'SHORT',
                        'size': abs(float(pos['positionAmt'])),
                        'entry_price': float(pos['entryPrice']),
                        'unrealized_pnl': float(pos.get('unRealizedProfit', 0)),
                        'leverage': int(pos.get('leverage', 0)),
                        'liquidation_price': float(pos.get('liquidationPrice', 0)),
                        'margin_type': pos.get('marginType', ''),
                    }
            return None
        except Exception as e:
            logger.error(f"Failed to get position for {symbol}: {e}")
            return None

    def get_all_positions(self) -> List[Dict]:
        """Get all open positions."""
        try:
            positions = self.client.futures_position_information()
            result = []
            for pos in positions:
                pos_dict = dict(pos)
                if float(pos_dict.get('positionAmt', 0)) != 0:
                    result.append({
                        'symbol': pos_dict.get('symbol', ''),
                        'side': 'LONG' if float(pos_dict.get('positionAmt', 0)) > 0 else 'SHORT',
                        'size': abs(float(pos_dict.get('positionAmt', 0))),
                        'entry_price': float(pos_dict.get('entryPrice', 0)),
                        'unrealized_pnl': float(pos_dict.get('unrealizedProfit', 0)),
                        'leverage': int(pos_dict.get('leverage', 0)),
                        'liquidation_price': float(pos_dict.get('liquidationPrice', 0)),
                        'margin_type': pos_dict.get('marginType', ''),
                    })
            self._positions = {p['symbol']: p for p in result}
            return result
        except Exception as e:
            logger.error(f"Failed to get positions: {e}")
            # Handle specific KeyError for unrealizedProfit
            if "'unrealizedProfit'" in str(e):
                logger.warning("API response missing 'unrealizedProfit' key, using fallback")
                # Retry with alternative key or skip
                return self._get_positions_fallback()
            return []

    def _round_price(self, symbol: str, price: float) -> float:
        """Round price to symbol's tick_size precision."""
        try:
            symbol_info = self.get_symbol_info(symbol)
            if not symbol_info:
                return price
            tick_size = symbol_info['tick_size']
            precision = len(str(tick_size).rstrip('0').split('.')[-1]) if '.' in str(tick_size) else 0
            return round(price - (price % tick_size), precision)
        except Exception:
            return price

    def open_position(self, symbol: str, side: str, quantity: float,
                      leverage: int = 5, stop_loss: float = None,
                      take_profit: float = None) -> Optional[Dict]:
        """
        Open a futures position.
        """
        try:
            # Set leverage
            self.client.futures_change_leverage(symbol=symbol, leverage=leverage)

            # Set margin type to ISOLATED
            try:
                self.client.futures_change_margin_type(symbol=symbol, marginType='ISOLATED')
            except BinanceAPIException:
                pass  # Already isolated

            # Place market order
            order_side = 'BUY' if side == 'LONG' else 'SELL'
            order = self.client.futures_create_order(
                symbol=symbol,
                side=order_side,
                type='MARKET',
                quantity=quantity
            )

            logger.info(f"Opened {side} position: {symbol} x{quantity} @ {order.get('avgPrice', 'market')}")

            result = {
                'symbol': symbol,
                'side': side,
                'quantity': quantity,
                'order_id': order.get('orderId'),
                'status': order.get('status'),
                'avg_price': float(order.get('avgPrice', 0)),
            }

            # Set stop loss with rounded precision
            if stop_loss:
                sl_price = self._round_price(symbol, stop_loss)
                sl_side = 'SELL' if side == 'LONG' else 'BUY'
                try:
                    self.client.futures_create_order(
                        symbol=symbol,
                        side=sl_side,
                        type='STOP_MARKET',
                        stopPrice=sl_price,
                        closePosition=True,
                        timeInForce='GTC'
                    )
                    result['stop_loss'] = sl_price
                    logger.info(f"Set SL for {symbol}: {sl_price}")
                except BinanceAPIException as e:
                    logger.error(f"Failed to set SL for {symbol}: {e}")

            # Set take profit with rounded precision
            if take_profit:
                tp_price = self._round_price(symbol, take_profit)
                tp_side = 'SELL' if side == 'LONG' else 'BUY'
                try:
                    self.client.futures_create_order(
                        symbol=symbol,
                        side=tp_side,
                        type='TAKE_PROFIT_MARKET',
                        stopPrice=tp_price,
                        closePosition=True,
                        timeInForce='GTC'
                    )
                    result['take_profit'] = tp_price
                    logger.info(f"Set TP for {symbol}: {tp_price}")
                except BinanceAPIException as e:
                    logger.error(f"Failed to set TP for {symbol}: {e}")

            return result

        except BinanceAPIException as e:
            logger.error(f"Failed to open position {symbol}: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error opening position {symbol}: {e}")
            return None

    def close_position(self, symbol: str) -> Optional[Dict]:
        """Close an open position for a symbol. Returns trade result dict."""
        try:
            position = self.get_position(symbol)
            if not position:
                logger.warning(f"No position found for {symbol}")
                return None

            # Cancel all open orders for the symbol first
            try:
                self.client.futures_cancel_all_open_orders(symbol=symbol)
            except Exception:
                pass

            close_side = 'SELL' if position['side'] == 'LONG' else 'BUY'
            order = self.client.futures_create_order(
                symbol=symbol,
                side=close_side,
                type='MARKET',
                quantity=position['size']
            )

            # Get realized PnL from income history
            import time
            pnl = self._get_realized_pnl(symbol)

            result = {
                'symbol': symbol,
                'side': position['side'],
                'entry_price': position['entry_price'],
                'close_price': float(order.get('avgPrice', 0)),
                'unrealized_pnl': position['unrealized_pnl'],
                'realized_pnl': pnl,
            }

            logger.info(f"Closed position: {symbol} ({position['side']}) PnL: {pnl:.2f} USDT")
            return result

        except Exception as e:
            logger.error(f"Failed to close position {symbol}: {e}")
            return None

    def _get_realized_pnl(self, symbol: str) -> float:
        """Get realized PnL for recently closed position from income history."""
        try:
            import time
            # Get income records from last 5 minutes
            end_time = int(time.time() * 1000)
            start_time = end_time - (5 * 60 * 1000)

            income = self.client.futures_income_history(
                symbol=symbol,
                startTime=start_time,
                endTime=end_time,
                limit=100
            )

            total_pnl = 0.0
            for record in income:
                income_type = record.get('incomeType', '')
                if income_type == 'REALIZED_PNL':
                    total_pnl += float(record.get('income', 0))

            return total_pnl
        except Exception as e:
            logger.error(f"Failed to get realized PnL for {symbol}: {e}")
            return 0.0

    def update_stop_loss(self, symbol: str, new_stop_loss: float, side: str) -> bool:
        """Update stop loss for an open position."""
        try:
            # Cancel existing SL orders
            open_orders = self.client.futures_get_open_orders(symbol=symbol)
            for order in open_orders:
                if order.get('type') in ['STOP_MARKET', 'STOP']:
                    self.client.futures_cancel_order(symbol=symbol, orderId=order['orderId'])

            # Set new SL
            sl_side = 'SELL' if side == 'LONG' else 'BUY'
            self.client.futures_create_order(
                symbol=symbol,
                side=sl_side,
                type='STOP_MARKET',
                stopPrice=new_stop_loss,
                closePosition=True,
                timeInForce='GTC'
            )
            logger.info(f"Updated SL for {symbol}: {new_stop_loss}")
            return True
        except Exception as e:
            logger.error(f"Failed to update SL for {symbol}: {e}")
            return False

    def get_symbol_info(self, symbol: str) -> Optional[Dict]:
        """Get trading rules for a symbol (min qty, precision, etc)."""
        try:
            exchange_info = self.client.futures_exchange_info()
            for s in exchange_info['symbols']:
                if s['symbol'] == symbol:
                    filters = {f['filterType']: f for f in s['filters']}
                    lot_size = filters.get('LOT_SIZE', {})
                    price_filter = filters.get('PRICE_FILTER', {})
                    return {
                        'symbol': symbol,
                        'status': s['status'],
                        'base_asset': s['baseAsset'],
                        'quote_asset': s['quoteAsset'],
                        'min_qty': float(lot_size.get('minQty', 0)),
                        'max_qty': float(lot_size.get('maxQty', 0)),
                        'step_size': float(lot_size.get('stepSize', 0)),
                        'min_price': float(price_filter.get('minPrice', 0)),
                        'tick_size': float(price_filter.get('tickSize', 0)),
                    }
            return None
        except Exception as e:
            logger.error(f"Failed to get symbol info for {symbol}: {e}")
            return None

    def calculate_quantity(self, symbol: str, usdt_amount: float, leverage: int = 5) -> float:
        """Calculate the correct quantity for a given USDT amount."""
        try:
            price = self.get_current_price(symbol)
            if not price:
                return 0.0

            symbol_info = self.get_symbol_info(symbol)
            if not symbol_info:
                return 0.0

            raw_qty = (usdt_amount * leverage) / price
            step_size = symbol_info['step_size']

            # Round down to step size
            precision = len(str(step_size).rstrip('0').split('.')[-1]) if '.' in str(step_size) else 0
            qty = round(raw_qty - (raw_qty % step_size), precision)

            # Ensure minimum quantity
            if qty < symbol_info['min_qty']:
                qty = symbol_info['min_qty']

            return qty
        except Exception as e:
            logger.error(f"Failed to calculate quantity for {symbol}: {e}")
            return 0.0
