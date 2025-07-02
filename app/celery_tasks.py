import os
import logging
from celery import Celery
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


def make_celery(app):
    """Create and configure Celery instance for Flask app."""
    celery = Celery(
        app.import_name,
        backend=app.config.get('CELERY_RESULT_BACKEND',
                               'redis://localhost:6379/0'),
        broker=app.config.get('CELERY_BROKER_URL', 'redis://localhost:6379/0')
    )

    # Update configuration from Flask app
    celery.conf.update(
        task_serializer='json',
        accept_content=['json'],
        result_serializer='json',
        timezone='UTC',
        enable_utc=True,
        result_expires=3600,  # Results expire after 1 hour
        task_routes={
            'file_processing.*': {'queue': 'file_processing'},
            'notifications.*': {'queue': 'notifications'},
            'cleanup.*': {'queue': 'cleanup'}
        },
        worker_prefetch_multiplier=1,
        task_acks_late=True,
        worker_max_tasks_per_child=1000
    )

    # Subclass task base for Flask app context
    class ContextTask(celery.Task):
        """Make celery tasks work with Flask app context."""

        def __call__(self, *args, **kwargs):
            with app.app_context():
                return self.run(*args, **kwargs)

    celery.Task = ContextTask
    return celery


# Initialize celery (will be set up when app is created)
celery = None


def init_celery(app):
    """Initialize Celery with Flask app."""
    global celery
    try:
        celery = make_celery(app)
        app.logger.info("Celery initialized successfully")
        return celery
    except Exception as e:
        app.logger.error(f"Failed to initialize Celery: {e}")
        return None

# Background task definitions


@celery.task(bind=True, name='file_processing.process_uploaded_file')
def process_uploaded_file(self, file_id, user_id, s3_key, file_type):
    """
    Background task to process uploaded files.

    Args:
        file_id: Unique file identifier
        user_id: User who uploaded the file
        s3_key: S3 object key
        file_type: MIME type of the file
    """
    try:
        logger.info(f"Starting file processing for file_id: {file_id}")

        # Update task status
        self.update_state(state='PROCESSING', meta={
                          'progress': 0, 'status': 'Starting file processing'})

        # Simulate file processing steps
        processing_steps = [
            ('Downloading file from S3', 20),
            ('Scanning for malware', 40),
            ('Extracting metadata', 60),
            ('Generating thumbnail', 80),
            ('Updating database', 100)
        ]

        results = {
            'file_id': file_id,
            'user_id': user_id,
            'processed_at': datetime.utcnow().isoformat(),
            'processing_steps': [],
            'thumbnail_url': None,
            'metadata': {},
            'security_scan': 'clean'
        }

        for step_name, progress in processing_steps:
            logger.info(f"Processing {file_id}: {step_name}")
            self.update_state(
                state='PROCESSING',
                meta={'progress': progress,
                      'status': step_name, 'file_id': file_id}
            )

            # Simulate processing time
            import time
            time.sleep(2)

            # Perform actual processing based on step
            if step_name == 'Downloading file from S3':
                # In real implementation, download file from S3
                results['processing_steps'].append({
                    'step': step_name,
                    'completed_at': datetime.utcnow().isoformat(),
                    'status': 'success'
                })

            elif step_name == 'Scanning for malware':
                # In real implementation, scan file with antivirus
                results['security_scan'] = 'clean'
                results['processing_steps'].append({
                    'step': step_name,
                    'completed_at': datetime.utcnow().isoformat(),
                    'status': 'success',
                    'result': 'No threats detected'
                })

            elif step_name == 'Extracting metadata':
                # In real implementation, extract file metadata
                results['metadata'] = {
                    'file_size_mb': 2.5,
                    'dimensions': '1920x1080' if 'image' in file_type else None,
                    'duration': '00:05:30' if 'video' in file_type else None,
                    'pages': 10 if 'pdf' in file_type else None
                }
                results['processing_steps'].append({
                    'step': step_name,
                    'completed_at': datetime.utcnow().isoformat(),
                    'status': 'success'
                })

            elif step_name == 'Generating thumbnail':
                # In real implementation, generate thumbnail
                if any(img_type in file_type for img_type in ['image', 'video', 'pdf']):
                    results[
                        'thumbnail_url'] = f"https://your-bucket.s3.amazonaws.com/thumbnails/{file_id}_thumb.jpg"
                results['processing_steps'].append({
                    'step': step_name,
                    'completed_at': datetime.utcnow().isoformat(),
                    'status': 'success'
                })

            elif step_name == 'Updating database':
                # Update DynamoDB with processing results
                try:
                    from app.dynamodb_manager import get_dynamodb_manager
                    db_manager = get_dynamodb_manager()
                    if db_manager:
                        update_result = db_manager.update_file_metadata(file_id, {
                            'processing_status': 'completed',
                            'processed_at': results['processed_at'],
                            'thumbnail_url': results['thumbnail_url'],
                            'metadata': results['metadata'],
                            'security_scan_result': results['security_scan']
                        })

                        if update_result['success']:
                            results['processing_steps'].append({
                                'step': step_name,
                                'completed_at': datetime.utcnow().isoformat(),
                                'status': 'success'
                            })
                        else:
                            raise Exception(
                                f"Database update failed: {update_result['error']}")
                except Exception as e:
                    logger.error(f"Database update failed: {e}")
                    results['processing_steps'].append({
                        'step': step_name,
                        'completed_at': datetime.utcnow().isoformat(),
                        'status': 'failed',
                        'error': str(e)
                    })

        logger.info(f"File processing completed for file_id: {file_id}")
        return {
            'status': 'SUCCESS',
            'result': results
        }

    except Exception as e:
        logger.error(f"File processing failed for file_id {file_id}: {e}")
        self.update_state(
            state='FAILURE',
            meta={'error': str(e), 'file_id': file_id}
        )
        raise


@celery.task(name='notifications.send_processing_complete')
def send_processing_complete_notification(user_id, file_id, filename):
    """
    Send notification when file processing is complete.

    Args:
        user_id: User to notify
        file_id: Processed file ID
        filename: Original filename
    """
    try:
        logger.info(
            f"Sending processing complete notification to user {user_id}")

        # In real implementation, send email, push notification, etc.
        notification_data = {
            'user_id': user_id,
            'file_id': file_id,
            'filename': filename,
            'message': f'Your file "{filename}" has been processed successfully!',
            'sent_at': datetime.utcnow().isoformat(),
            'type': 'file_processing_complete'
        }

        # Simulate sending notification
        import time
        time.sleep(1)

        logger.info(f"Notification sent successfully to user {user_id}")
        return notification_data

    except Exception as e:
        logger.error(f"Failed to send notification to user {user_id}: {e}")
        raise


@celery.task(name='cleanup.delete_old_files')
def cleanup_old_files(days_old=30):
    """
    Clean up old files from S3 and database.

    Args:
        days_old: Files older than this many days will be deleted
    """
    try:
        logger.info(f"Starting cleanup of files older than {days_old} days")

        cutoff_date = datetime.utcnow() - timedelta(days=days_old)
        deleted_count = 0

        # In real implementation:
        # 1. Query DynamoDB for old files
        # 2. Delete from S3
        # 3. Remove from DynamoDB
        # 4. Log cleanup results

        # Simulate cleanup
        import time
        time.sleep(5)

        cleanup_result = {
            'deleted_files': deleted_count,
            'cutoff_date': cutoff_date.isoformat(),
            'completed_at': datetime.utcnow().isoformat()
        }

        logger.info(f"Cleanup completed: {deleted_count} files deleted")
        return cleanup_result

    except Exception as e:
        logger.error(f"Cleanup failed: {e}")
        raise


@celery.task(name='file_processing.batch_process_files')
def batch_process_files(file_ids):
    """
    Process multiple files in batch.

    Args:
        file_ids: List of file IDs to process
    """
    try:
        logger.info(f"Starting batch processing of {len(file_ids)} files")

        results = []
        for file_id in file_ids:
            # Queue individual processing tasks
            task = process_uploaded_file.delay(
                file_id, 1, f"files/{file_id}", "application/pdf")
            results.append({
                'file_id': file_id,
                'task_id': task.id
            })

        return {
            'batch_id': f"batch_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}",
            'total_files': len(file_ids),
            'queued_tasks': results
        }

    except Exception as e:
        logger.error(f"Batch processing failed: {e}")
        raise


# Periodic tasks (would be configured with celery beat)
@celery.task(name='maintenance.daily_maintenance')
def daily_maintenance():
    """Run daily maintenance tasks."""
    try:
        logger.info("Starting daily maintenance")

        # Queue cleanup task
        cleanup_task = cleanup_old_files.delay(30)

        # Other maintenance tasks...

        return {
            'maintenance_date': datetime.utcnow().isoformat(),
            'tasks_queued': [cleanup_task.id],
            'status': 'completed'
        }

    except Exception as e:
        logger.error(f"Daily maintenance failed: {e}")
        raise


# Task monitoring helpers
def get_task_status(task_id):
    """Get the status of a background task."""
    try:
        if not celery:
            return {'status': 'ERROR', 'message': 'Celery not initialized'}

        task = celery.AsyncResult(task_id)

        if task.state == 'PENDING':
            response = {
                'status': 'PENDING',
                'progress': 0,
                'message': 'Task is waiting to be processed'
            }
        elif task.state == 'PROCESSING':
            response = {
                'status': 'PROCESSING',
                'progress': task.info.get('progress', 0),
                'message': task.info.get('status', 'Processing...'),
                'file_id': task.info.get('file_id')
            }
        elif task.state == 'SUCCESS':
            response = {
                'status': 'SUCCESS',
                'progress': 100,
                'result': task.info
            }
        else:  # FAILURE
            response = {
                'status': 'FAILURE',
                'progress': 0,
                'error': str(task.info),
                'message': 'Task failed'
            }

        return response

    except Exception as e:
        logger.error(f"Error getting task status: {e}")
        return {'status': 'ERROR', 'message': str(e)}


def cancel_task(task_id):
    """Cancel a background task."""
    try:
        if not celery:
            return {'success': False, 'error': 'Celery not initialized'}

        celery.control.revoke(task_id, terminate=True)
        return {'success': True, 'message': f'Task {task_id} cancelled'}

    except Exception as e:
        logger.error(f"Error cancelling task: {e}")
        return {'success': False, 'error': str(e)}
