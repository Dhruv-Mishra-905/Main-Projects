# NetPulse Smart Network Analytics Center (SNAC)

Flask backend for the NetPulse dashboard.

## Run

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000`.

Default login:

- Email: `admin@netpulse.local`
- Password: `admin123`

## Backend features

- Flask routes for login and dashboard pages
- SQLite database created automatically in `netpulse.db`
- Session-based authentication
- Seeded admin user and sample network devices
- JSON APIs for dashboard summary, devices, and live simulation
