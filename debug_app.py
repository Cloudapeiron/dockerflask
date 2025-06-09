from app import create_app
import traceback

if __name__ == '__main__':
    try:
        print("Attempting to create Flask app...")
        app = create_app()
        print(f"App created: {app}")
        print(f"App type: {type(app)}")

        if app:
            print("Starting Flask app...")
            app.run(debug=True, host='0.0.0.0', port=5000)
        else:
            print("create_app() returned None")

    except Exception as e:
        print(f"Error creating app: {e}")
        print(f"Exception type: {type(e).__name__}")
        print("Full traceback:")
        traceback.print_exc()
