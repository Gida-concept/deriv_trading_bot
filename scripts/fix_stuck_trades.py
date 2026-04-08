import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from database.db_conn import execute_query

execute_query("UPDATE trades SET status = 'lost', closed_at = NOW() WHERE status = 'open'")
print("All stuck open positions marked as lost")
