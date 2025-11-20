#!/usr/bin/env python3
"""
Database Initialization Script
Run this script to initialize MongoDB collections with schemas and indexes
"""

import sys
from flask import Flask
from flask_pymongo import PyMongo
from config import config
from database import init_database, create_indexes
from database.schemas import get_collection_stats
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def main():
    """Initialize database"""
    # Get command line arguments
    drop_existing = '--drop' in sys.argv
    env = 'development'

    if '--production' in sys.argv:
        env = 'production'
    elif '--testing' in sys.argv:
        env = 'testing'

    logger.info(f"Initializing database in {env} environment")

    if drop_existing:
        logger.warning("WARNING: --drop flag provided. All existing data will be deleted!")
        response = input("Are you sure you want to continue? (yes/no): ")
        if response.lower() != 'yes':
            logger.info("Initialization cancelled")
            return

    # Create Flask app
    app = Flask(__name__)
    app.config.from_object(config[env])

    # Initialize PyMongo
    mongo = PyMongo(app)

    try:
        # Test connection
        mongo.db.command('ping')
        logger.info("Successfully connected to MongoDB")

        # Initialize collections
        logger.info("Initializing collections with schemas...")
        init_results = init_database(mongo.db, drop_existing=drop_existing)

        # Print results
        logger.info("\nCollection Initialization Results:")
        for collection, success in init_results.items():
            status = "✓ SUCCESS" if success else "✗ FAILED"
            logger.info(f"  {collection}: {status}")

        # Get statistics
        logger.info("\nCollection Statistics:")
        stats = get_collection_stats(mongo.db)
        for collection, info in stats.items():
            if 'error' in info:
                logger.error(f"  {collection}: ERROR - {info['error']}")
            else:
                size_mb = info['size_bytes'] / 1024 / 1024
                logger.info(
                    f"  {collection}: {info['count']} documents, "
                    f"{info['indexes']} indexes, {size_mb:.2f} MB"
                )

        logger.info("\nDatabase initialization completed successfully!")

    except Exception as e:
        logger.error(f"Error during initialization: {e}")
        sys.exit(1)


if __name__ == '__main__':
    if '--help' in sys.argv or '-h' in sys.argv:
        print("""
Database Initialization Script

Usage:
  python init_db.py [options]

Options:
  --drop         Drop existing collections (CAUTION: deletes all data!)
  --production   Use production configuration
  --testing      Use testing configuration
  --help, -h     Show this help message

Examples:
  # Initialize database (development environment)
  python init_db.py

  # Initialize database in production
  python init_db.py --production

  # Reinitialize database (drops all data)
  python init_db.py --drop

  # Initialize test database
  python init_db.py --testing
        """)
        sys.exit(0)

    main()
