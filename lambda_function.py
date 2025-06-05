from app import create_app

# Create Flask app instance
app = create_app('production')  # Use production config for Lambda

# For Zappa, we just need to expose the app object
# Zappa handles the WSGI integration automatically
