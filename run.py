#!/usr/bin/env python3
"""
Flask Application Entry Point
Production-ready runner with debugging for Docker deployment
"""

import os
import sys
import logging
from app import create_app


def setup_logging():
    """Configure logging for debugging"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(
                '/app/logs/app.log') if os.path.exists('/app/logs') else logging.NullHandler()
        ]
    )
    return logging.getLogger(__name__)


def main():
    logger = setup_logging()

    try:
        # Show environment info
        flask_env = os.environ.get('FLASK_ENV', 'development')
        database_url = os.environ.get('DATABASE_URL', 'not set')

        logger.info(f"Starting Flask application...")
        logger.info(f"FLASK_ENV: {flask_env}")
        logger.info(f"DATABASE_URL: {database_url}")
        logger.info(f"Python version: {sys.version}")

        # Create Flask application instance
        logger.info("Creating Flask app...")
        app = create_app()

        # Create database tables if they don't exist
        logger.info("Initializing database...")
        with app.app_context():
            from app.models import db
            db.create_all()
            logger.info("Database tables initialized successfully")

        # Get configuration from environment variables
        host = os.environ.get('FLASK_HOST', '0.0.0.0')
        port = int(os.environ.get('FLASK_PORT', 5000))
        debug = flask_env == 'development'

        logger.info(f"Starting Flask app on {host}:{port}")
        logger.info(f"Debug mode: {debug}")

        app.run(
            host=host,
            port=port,
            debug=debug,
            threaded=True
        )

    except Exception as e:
        logger.error(f"Failed to start application: {str(e)}")
        logger.error(f"Exception type: {type(e).__name__}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        sys.exit(1)


if __name__ == '__main__':
    main()
