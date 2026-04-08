-- Migration: Add profit_loss_pct column to trades table
-- Run this on your existing database to add PnL percentage tracking

ALTER TABLE trades 
ADD COLUMN IF NOT EXISTS profit_loss_pct DECIMAL(10,4);

-- Add index for faster queries on PnL percentage
CREATE INDEX IF NOT EXISTS idx_trades_profit_loss_pct ON trades(profit_loss_pct);

-- Optional: Update existing closed trades with calculated PnL percentage
-- This requires knowing the stake_amount and leverage for each trade
-- The bot_engine.py will handle this for new trades automatically
