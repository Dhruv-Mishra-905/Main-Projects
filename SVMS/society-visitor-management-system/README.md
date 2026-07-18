# Society Visitor Management System

A simple Flask-based visitor management system for society admins and security guards.

## Project structure

- `app.py` - Flask application entry point
- `requirements.txt` - Python dependencies
- `society.db` - SQLite database file
- `templates/` - HTML templates for login, registration, dashboards, and error pages
- `static/css/style.css` - shared stylesheet
- `static/images/` - image assets

## Setup

1. Create a virtual environment:
   ```bash
   python -m venv venv
   ```
2. Activate the environment:
   - Windows: `venv\\Scripts\\activate`
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Run the app:
   ```bash
   python app.py
   ```

Open `http://127.0.0.1:5000` in your browser.
