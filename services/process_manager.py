# services/process_manager.py
import asyncio
import threading
import logging
from typing import Dict, Any, Optional, List
from services.bot_engine import BotEngine, get_or_create_bot, remove_bot
from utils.logger import log_audit_event

logger = logging.getLogger(__name__)

class ProcessManager:
    """
    Lightweight ProcessManager that matches what user_api.py expects
    """
    def __init__(self):
        self.active_bots = {}  # (user_id, timeframe) -> BotEngine
        self._lock = threading.Lock()

    def spawn_bot_thread(self, user_id: int, timeframe: str, strategy: str = 'default'):
        key = (user_id, timeframe.upper())
        with self._lock:
            if key in self.active_bots:
                logger.warning(f"Bot already running: {key}")
                return

            bot = get_or_create_bot(user_id, timeframe.upper(), strategy)
            if not bot:
                logger.error("Failed to create bot")
                return

            def run_bot():
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    loop.run_until_complete(bot.run())
                finally:
                    loop.close()

            thread = threading.Thread(target=run_bot, daemon=True)
            thread.start()

            self.active_bots[key] = bot
            logger.info(f"Bot started: user {user_id}, timeframe {timeframe}")

    def stop_bot_thread(self, user_id: int, timeframe: str):
        key = (user_id, timeframe.upper())
        with self._lock:
            bot = self.active_bots.pop(key, None)

        if bot:
            bot.running = False
            if bot.client:
                try:
                    bot.client.disconnect()
                except Exception as e:
                    logger.error(f"Error disconnecting client for {key}: {e}")
            remove_bot(user_id, timeframe)
            logger.info(f"Bot stopped and removed: {key}")

    def get_bot_status(self, user_id: int, timeframe: str = None):
        result = []
        with self._lock:
            for (uid, tf), bot in self.active_bots.items():
                if uid == user_id and (timeframe is None or tf == timeframe.upper()):
                    result.append({
                        "timeframe": tf,
                        "running": getattr(bot, 'running', False),
                        "trades": getattr(bot, 'trades_executed', 0)
                    })
        return {"bots": result}


# Global singleton
_process_manager = None

def get_process_manager():
    global _process_manager
    if _process_manager is None:
        _process_manager = ProcessManager()
    return _process_manager

__all__ = ['ProcessManager', 'get_process_manager']