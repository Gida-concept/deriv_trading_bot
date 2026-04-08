import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from database.db_conn import execute_query_all

# Check what status values are allowed
result = execute_query_all("""
    SELECT pg_get_constraintdef(oid) 
    FROM pg_constraint 
    WHERE conrelid = 'trades'::regclass AND contype = 'c'
""")
print("Constraints:", result)

# Check what statuses exist
result2 = execute_query_all("SELECT DISTINCT status FROM trades")
print("Existing statuses:", result2)
