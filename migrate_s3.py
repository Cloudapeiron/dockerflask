#!/usr/bin/env python3
"""
Database migration script to add S3 support to existing UploadedFile table.
Run this script to add the new S3 columns to your existing database.

Usage:
    python migrate_s3.py
"""

import os
import sys
from flask import Flask
from app import create_app
from app.models import db, UploadedFile
from sqlalchemy import text


def migrate_database():
    """Add S3 columns to existing UploadedFile table."""

    app = create_app()

    with app.app_context():
        try:
            # Check if columns already exist
            inspector = db.inspect(db.engine)
            columns = [c['name']
                       for c in inspector.get_columns('uploaded_file')]

            print("Current columns in uploaded_file table:", columns)

            # Add new columns if they don't exist
            new_columns = {
                's3_url': 'VARCHAR(1000)',
                'storage_type': 'VARCHAR(20) DEFAULT "local"',
                's3_key': 'VARCHAR(500)'
            }

            for column_name, column_def in new_columns.items():
                if column_name not in columns:
                    print(f"Adding column: {column_name}")

                    # Use text() for SQLAlchemy 2.x compatibility
                    sql = f'ALTER TABLE uploaded_file ADD COLUMN {column_name} {column_def}'

                    with db.engine.connect() as conn:
                        conn.execute(text(sql))
                        conn.commit()

                    print(f"✅ Added column: {column_name}")
                else:
                    print(f"⚠️  Column {column_name} already exists")

            # Update existing records to have storage_type = 'local'
            print("Updating existing records to set storage_type = 'local'...")

            # Use text() for the update query
            with db.engine.connect() as conn:
                result = conn.execute(
                    text(
                        "UPDATE uploaded_file SET storage_type = 'local' WHERE storage_type IS NULL OR storage_type = ''")
                )
                updated_count = result.rowcount
                conn.commit()

            print(
                f"✅ Updated {updated_count} existing files to local storage type")
            print("🎉 Migration completed successfully!")

        except Exception as e:
            print(f"❌ Migration failed: {e}")
            return False

    return True


def verify_migration():
    """Verify that the migration was successful."""

    app = create_app()

    with app.app_context():
        try:
            # Test the new columns
            inspector = db.inspect(db.engine)
            columns = [c['name']
                       for c in inspector.get_columns('uploaded_file')]

            required_columns = ['s3_url', 'storage_type', 's3_key']
            missing_columns = [
                col for col in required_columns if col not in columns]

            if missing_columns:
                print(f"❌ Missing columns: {missing_columns}")
                return False

            # Test querying with new columns
            file_count = UploadedFile.query.count()
            local_files = UploadedFile.query.filter_by(
                storage_type='local').count()

            print(f"✅ Migration verification passed!")
            print(f"   Total files: {file_count}")
            print(f"   Local storage files: {local_files}")
            print(f"   All new columns present: {required_columns}")

            return True

        except Exception as e:
            print(f"❌ Verification failed: {e}")
            return False


if __name__ == '__main__':
    print("🚀 Starting S3 database migration...")
    print("=" * 50)

    if migrate_database():
        print("\n🔍 Verifying migration...")
        print("=" * 50)
        verify_migration()
    else:
        print("❌ Migration failed, please check the error messages above.")
        sys.exit(1)

    print("\n✨ Migration process completed!")
    print("Your database is now ready for S3 integration.")
    print("\nNext steps:")
    print("1. Set up your AWS S3 credentials in environment variables")
    print("2. Update your Docker configuration with S3 settings")
    print("3. Test file uploads with S3 enabled")
