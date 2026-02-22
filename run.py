from app import create_app

app = create_app()

if __name__ == "__main__":
    # Disable reloader on Windows to avoid OSError [WinError 10038]
    app.run(debug=True, port=5000, use_reloader=False)

