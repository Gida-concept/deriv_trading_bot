# scripts/add_pnl_percentage.py
"""Add pnl_percentage column to trades table if it doesn't exist."""
import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from database.db_conn import execute_query

try:
    execute_query("""
        ALTER TABLE trades ADD COLUMN IF NOT EXISTS pnl_percentage NUMERIC(10, 2) DEFAULT 0.0
    """)
    print("pnl_percentage column added to trades table")
except Exception as e:
    print(f"Error: {e}")
