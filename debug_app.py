from app import create_app
import traceback

if __name__ == '__main__':
    try:
        print("Attempting to create Flask app...")
        app = create_app()
        print(f"App created: {app}")
        print(f"App type: {type(app)}")

        # Add development user when running locally
        if app:
            with app.app_context():
                try:
                    from app.jwt_auth import UserManager

                    # Create a dev user if it doesn't exist
                    print("Creating development user...")
                    result = UserManager.create_user(
                        'admin', 'admin@test.com', 'password')
                    if result['success']:
                        print("✅ Created dev user: admin/password")
                    else:
                        print(
                            f"ℹ️  Dev user status: {result.get('error', 'User might already exist')}")
                except Exception as user_error:
                    print(f"User creation error: {user_error}")
                    print("You might need to register a user manually at /register")

            print("Starting Flask app...")
            app.run(debug=True, host='0.0.0.0', port=5000)
        else:
            print("create_app() returned None")

    except Exception as e:
        print(f"Error creating app: {e}")
        print(f"Exception type: {type(e).__name__}")
        print("Full traceback:")
        traceback.print_exc()
