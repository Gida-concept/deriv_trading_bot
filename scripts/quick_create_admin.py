#!/usr/bin/env python3
"""
Quick admin creation - no emojis, no interactive prompts.
Usage: python scripts/quick_create_admin.py <email> <password>
"""

import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.hasher import hash_password
from database.db_conn import execute_query, execute_insert_returning

def main():
    if len(sys.argv) < 3:
        print("Usage: python scripts/quick_create_admin.py <email> <password>")
        print("Example: python scripts/quick_create_admin.py admin@example.com MySecurePass123!")
        sys.exit(1)

    email = sys.argv[1].strip().lower()
    password = sys.argv[2]

    if len(password) < 12:
        print("Error: Password must be at least 12 characters.")
        sys.exit(1)

    # Check if exists
    existing = execute_query(
        "SELECT id FROM admin_accounts WHERE email = %s",
        (email,),
        fetch_one=True
    )

    if existing:
        print(f"Admin already exists with ID: {existing['id']}")
        sys.exit(0)

    # Create
    password_hash = hash_password(password)
    result = execute_insert_returning(
        table_name='admin_accounts',
        columns=['email', 'password_hash', 'is_active', 'status'],
        values=[email, password_hash, True, 'active'],
        returning_columns='id'
    )

    print(f"Admin created successfully! ID: {result['id']}")
    print(f"Email: {email}")
    print("You can now login at http://localhost:5000/admin/login")

if __name__ == '__main__':
    main()
