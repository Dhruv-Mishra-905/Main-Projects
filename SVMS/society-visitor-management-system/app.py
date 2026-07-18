from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from io import BytesIO
import json
import sqlite3
import random
import string
import os
import time
from datetime import datetime, timedelta
from pathlib import Path
from xml.sax.saxutils import escape
from dotenv import load_dotenv
import otp_service
from reportlab.graphics.barcode import qr
from reportlab.graphics.shapes import Drawing
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Image, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

load_dotenv()

BASE_DIR = Path(__file__).parent
DB_PATH = BASE_DIR / "society.db"
UPLOAD_FOLDER = BASE_DIR / "static" / "uploads"
UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)
ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'gif'}
SOCIETY_NAME = "Society Visitor Management System"
SOCIETY_LOGO_PATH = BASE_DIR / "static" / "images" / "logo.png"
PASS_VALIDITY_HOURS = 24

app = Flask(__name__, static_folder="static", template_folder="templates")
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "replace-with-a-secure-secret")
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024


def int_env(name, default):
    try:
        return max(1, int(os.environ.get(name, default)))
    except (TypeError, ValueError):
        return default


OTP_SEND_LIMIT = int_env("OTP_SEND_LIMIT", 3)
OTP_SEND_WINDOW_SECONDS = int_env("OTP_SEND_WINDOW_SECONDS", 180)


def get_table_columns(cursor, table_name):
    cursor.execute(f"PRAGMA table_info({table_name})")
    return {row[1] for row in cursor.fetchall()}


def ensure_columns(cursor, table_name, column_definitions):
    existing_columns = get_table_columns(cursor, table_name)
    for column_name, column_definition in column_definitions:
        if column_name not in existing_columns:
            cursor.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_definition}")
            existing_columns.add(column_name)


def is_werkzeug_hash(value):
    return isinstance(value, str) and value.startswith(("scrypt:", "pbkdf2:"))


def migrate_password_column(cursor, table_name):
    columns = get_table_columns(cursor, table_name)
    if "password" not in columns or "password_hash" not in columns:
        return

    cursor.execute(
        f"""
        SELECT id, password
        FROM {table_name}
        WHERE (password_hash IS NULL OR password_hash = '')
          AND password IS NOT NULL
          AND password != ''
        """
    )
    for row_id, password in cursor.fetchall():
        password_hash = password if is_werkzeug_hash(password) else generate_password_hash(password)
        cursor.execute(
            f"UPDATE {table_name} SET password_hash = ? WHERE id = ?",
            (password_hash, row_id),
        )


def drop_legacy_password_column(cursor, table_name):
    if "password" in get_table_columns(cursor, table_name):
        cursor.execute(f"ALTER TABLE {table_name} DROP COLUMN password")


def migrate_existing_schema(cursor):
    user_columns = [
        ("password_hash", "TEXT"),
        ("full_name", "TEXT"),
        ("profile_photo", "TEXT"),
        ("dob", "TEXT"),
        ("gender", "TEXT"),
        ("email", "TEXT"),
        ("email_verified", "BOOLEAN DEFAULT 0"),
        ("phone", "TEXT"),
        ("phone_verified", "BOOLEAN DEFAULT 0"),
        ("alternate_phone", "TEXT"),
        ("emergency_contact_name", "TEXT"),
        ("emergency_contact_number", "TEXT"),
        ("aadhaar_number", "TEXT"),
        ("pan_number", "TEXT"),
        ("id_document", "TEXT"),
        ("flat_no", "TEXT"),
        ("wing", "TEXT"),
        ("floor_no", "TEXT"),
        ("tower_name", "TEXT"),
        ("ownership_type", "TEXT"),
        ("move_in_date", "TEXT"),
        ("address", "TEXT"),
        ("city", "TEXT"),
        ("state", "TEXT"),
        ("pincode", "TEXT"),
        ("country", "TEXT DEFAULT 'India'"),
        ("vehicle_count", "INTEGER DEFAULT 0"),
        ("account_status", "TEXT DEFAULT 'pending'"),
        ("created_at", "TIMESTAMP"),
        ("updated_at", "TIMESTAMP"),
    ]
    pending_request_columns = [
        ("password_hash", "TEXT"),
        ("full_name", "TEXT"),
        ("profile_photo", "TEXT"),
        ("dob", "TEXT"),
        ("gender", "TEXT"),
        ("email", "TEXT"),
        ("email_verified", "BOOLEAN DEFAULT 0"),
        ("email_otp", "VARCHAR(6)"),
        ("phone", "TEXT"),
        ("phone_verified", "BOOLEAN DEFAULT 0"),
        ("phone_otp", "VARCHAR(6)"),
        ("alternate_phone", "TEXT"),
        ("emergency_contact_name", "TEXT"),
        ("emergency_contact_number", "TEXT"),
        ("aadhaar_number", "TEXT"),
        ("aadhaar_front", "TEXT"),
        ("aadhaar_back", "TEXT"),
        ("pan_number", "TEXT"),
        ("id_document_type", "TEXT"),
        ("id_document", "TEXT"),
        ("selfie", "TEXT"),
        ("flat_no", "TEXT"),
        ("wing", "TEXT"),
        ("floor_no", "TEXT"),
        ("tower_name", "TEXT"),
        ("ownership_type", "TEXT"),
        ("move_in_date", "TEXT"),
        ("num_family_members", "INTEGER"),
        ("address", "TEXT"),
        ("city", "TEXT"),
        ("state", "TEXT"),
        ("pincode", "TEXT"),
        ("country", "TEXT DEFAULT 'India'"),
        ("vehicle_count", "INTEGER DEFAULT 0"),
        ("security_question", "TEXT"),
        ("security_answer", "TEXT"),
        ("account_status", "TEXT DEFAULT 'pending'"),
        ("role", "TEXT DEFAULT 'user'"),
        ("created_at", "TIMESTAMP"),
    ]
    visitor_request_columns = [
        ("id_proof_number", "TEXT"),
        ("pass_generated_at", "TIMESTAMP"),
        ("pass_valid_from", "TIMESTAMP"),
        ("pass_valid_until", "TIMESTAMP"),
    ]

    ensure_columns(cursor, "users", user_columns)
    ensure_columns(cursor, "pending_requests", pending_request_columns)
    ensure_columns(cursor, "visitor_requests", visitor_request_columns)
    migrate_password_column(cursor, "users")
    migrate_password_column(cursor, "pending_requests")
    drop_legacy_password_column(cursor, "users")
    drop_legacy_password_column(cursor, "pending_requests")

    cursor.execute("UPDATE users SET country = 'India' WHERE country IS NULL OR country = ''")
    cursor.execute("UPDATE users SET vehicle_count = 0 WHERE vehicle_count IS NULL")
    cursor.execute("UPDATE users SET account_status = 'approved' WHERE account_status IS NULL OR account_status = ''")
    cursor.execute("UPDATE users SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL OR created_at = ''")
    cursor.execute("UPDATE users SET updated_at = CURRENT_TIMESTAMP WHERE updated_at IS NULL OR updated_at = ''")
    cursor.execute("UPDATE pending_requests SET country = 'India' WHERE country IS NULL OR country = ''")
    cursor.execute("UPDATE pending_requests SET vehicle_count = 0 WHERE vehicle_count IS NULL")
    cursor.execute("UPDATE pending_requests SET account_status = 'pending' WHERE account_status IS NULL OR account_status = ''")
    cursor.execute("UPDATE pending_requests SET role = 'user' WHERE role IS NULL OR role = ''")
    cursor.execute("UPDATE pending_requests SET email_verified = 0 WHERE email_verified IS NULL")
    cursor.execute("UPDATE pending_requests SET phone_verified = 0 WHERE phone_verified IS NULL")
    cursor.execute("UPDATE pending_requests SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL OR created_at = ''")


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def generate_otp():
    return ''.join(random.choices(string.digits, k=6))


def format_wait(seconds):
    seconds = max(1, int(seconds))
    minutes, remainder = divmod(seconds, 60)
    if minutes and remainder:
        return f"{minutes} min {remainder} sec"
    if minutes:
        return f"{minutes} min"
    return f"{seconds} sec"


def now_timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def dict_rows(query, params=()):
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(query, params)
        return [dict(row) for row in cursor.fetchall()]


def dict_row(query, params=()):
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(query, params)
        row = cursor.fetchone()
        return dict(row) if row else None


def scalar(query, params=(), default=0):
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        row = cursor.fetchone()
        return row[0] if row and row[0] is not None else default


def generate_token():
    return "SV-" + ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))


def generate_unique_pass_id(cursor):
    for _ in range(20):
        pass_id = generate_token()
        cursor.execute("SELECT 1 FROM visitor_requests WHERE token = ?", (pass_id,))
        if not cursor.fetchone():
            return pass_id
    return f"SV-{int(time.time())}"


def parse_db_timestamp(value):
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M"):
        try:
            return datetime.strptime(str(value), fmt)
        except ValueError:
            continue
    return None


def format_pass_time(value):
    dt = parse_db_timestamp(value)
    if dt:
        return dt.strftime("%d %b %Y, %I:%M %p")
    return value or "-"


def is_pass_expired(visitor):
    valid_until = parse_db_timestamp(visitor.get("pass_valid_until"))
    return bool(valid_until and datetime.now() > valid_until and not visitor.get("check_in_at"))


def effective_pass_status(visitor):
    if visitor.get("check_out_at"):
        return "Checked Out"
    if visitor.get("check_in_at"):
        return "Checked In"
    if visitor.get("status") == "approved" and is_pass_expired(visitor):
        return "Expired"
    if visitor.get("status") == "approved":
        return "Approved"
    if visitor.get("status") == "pending":
        return "Pending"
    return (visitor.get("status") or "Pending").replace("_", " ").title()


def enrich_pass_record(visitor):
    visitor["pass_id"] = visitor.get("token") or "-"
    visitor["pass_status"] = effective_pass_status(visitor)
    visitor["pass_status_key"] = visitor["pass_status"].lower().replace(" ", "-")
    visitor["pass_is_generated"] = bool(visitor.get("pass_generated_at"))
    visitor["pass_is_expired"] = is_pass_expired(visitor)
    visitor["pass_valid_from_display"] = format_pass_time(visitor.get("pass_valid_from"))
    visitor["pass_valid_until_display"] = format_pass_time(visitor.get("pass_valid_until"))
    return visitor


def visitor_pass_query(where_clause, params=(), limit=None):
    limit_sql = f" LIMIT {int(limit)}" if limit else ""
    visitors = dict_rows(
        f"""SELECT vr.*, COALESCE(u.full_name, u.username, vr.resident_name) AS resident_full_name,
                  COALESCE(u.phone, '') AS resident_phone,
                  COALESCE(g.full_name, g.username, 'Gate desk') AS guard_name
           FROM visitor_requests vr
           LEFT JOIN users u ON u.id = vr.resident_id
           LEFT JOIN users g ON g.id = vr.created_by_guard_id
           WHERE {where_clause}
           ORDER BY vr.id DESC{limit_sql}""",
        params,
    )
    return [enrich_pass_record(visitor) for visitor in visitors]


def get_visitor_pass(visitor_id):
    visitors = visitor_pass_query("vr.id = ?", (visitor_id,))
    return visitors[0] if visitors else None


def pass_qr_payload(visitor):
    return json.dumps(
        {
            "society": SOCIETY_NAME,
            "pass_id": visitor.get("token"),
            "visitor": visitor.get("visitor_name"),
            "phone": visitor.get("visitor_phone"),
            "purpose": visitor.get("purpose"),
            "flat": visitor.get("flat_no"),
            "resident": visitor.get("resident_full_name") or visitor.get("resident_name"),
            "guard": visitor.get("guard_name"),
            "valid_until": visitor.get("pass_valid_until"),
            "status": effective_pass_status(visitor),
        },
        separators=(",", ":"),
    )


def qr_drawing(payload, size=38 * mm):
    qr_code = qr.QrCodeWidget(payload)
    bounds = qr_code.getBounds()
    width = bounds[2] - bounds[0]
    height = bounds[3] - bounds[1]
    drawing = Drawing(
        size,
        size,
        transform=[size / width, 0, 0, size / height, 0, 0],
    )
    drawing.add(qr_code)
    return drawing


def paragraph(text, style):
    return Paragraph(escape(str(text or "-")), style)


def build_visitor_pass_pdf(visitor):
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=16 * mm,
        bottomMargin=16 * mm,
        title=f"Visitor Pass {visitor.get('token')}",
    )

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="PassTitle", parent=styles["Title"], fontSize=18, leading=22, alignment=TA_CENTER))
    styles.add(ParagraphStyle(name="PassSubtitle", parent=styles["Normal"], fontSize=9, leading=12, alignment=TA_CENTER, textColor=colors.HexColor("#475569")))
    styles.add(ParagraphStyle(name="PassRight", parent=styles["Normal"], fontSize=10, leading=13, alignment=TA_RIGHT))
    styles.add(ParagraphStyle(name="PassLabel", parent=styles["Normal"], fontSize=8, leading=11, textColor=colors.HexColor("#334155")))
    styles.add(ParagraphStyle(name="PassValue", parent=styles["Normal"], fontSize=9.5, leading=12, textColor=colors.HexColor("#0f172a")))

    logo = paragraph("SVMS", styles["PassTitle"])
    if SOCIETY_LOGO_PATH.exists():
        logo = Image(str(SOCIETY_LOGO_PATH), width=24 * mm, height=24 * mm, kind="proportional")

    header = Table(
        [
            [
                logo,
                Paragraph(f"<b>{SOCIETY_NAME}</b><br/><font size='10'>Visitor Pass | Entry Pass | Digital Pass</font>", styles["PassTitle"]),
                Paragraph(f"<b>Pass ID</b><br/>{escape(visitor.get('token') or '-')}", styles["PassRight"]),
            ]
        ],
        colWidths=[30 * mm, 92 * mm, 50 * mm],
    )
    header.setStyle(
        TableStyle(
            [
                ("BOX", (0, 0), (-1, -1), 1.4, colors.HexColor("#0f172a")),
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 9),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 9),
            ]
        )
    )

    entry_time = visitor.get("check_in_at") or visitor.get("pass_valid_from") or visitor.get("created_at")
    details = [
        ("Visitor name", visitor.get("visitor_name"), "Phone number", visitor.get("visitor_phone")),
        ("Purpose of visit", visitor.get("purpose"), "Person to meet", visitor.get("resident_full_name") or visitor.get("resident_name")),
        ("Flat number", visitor.get("flat_no"), "Resident/Owner name", visitor.get("resident_full_name") or visitor.get("resident_name")),
        ("Guard name", visitor.get("guard_name"), "Date and time of entry", format_pass_time(entry_time)),
        ("Valid from time", format_pass_time(visitor.get("pass_valid_from")), "Valid until time", format_pass_time(visitor.get("pass_valid_until"))),
        ("Check-in time", format_pass_time(visitor.get("check_in_at")), "Check-out time", format_pass_time(visitor.get("check_out_at"))),
        ("Status", effective_pass_status(visitor), "Vehicle number", visitor.get("vehicle_number") or "Optional"),
        ("ID proof number", visitor.get("id_proof_number") or "Optional", "Pass generated", format_pass_time(visitor.get("pass_generated_at"))),
    ]
    table_data = []
    for left_label, left_value, right_label, right_value in details:
        table_data.append(
            [
                Paragraph(f"<b>{escape(left_label)}</b>", styles["PassLabel"]),
                paragraph(left_value, styles["PassValue"]),
                Paragraph(f"<b>{escape(right_label)}</b>", styles["PassLabel"]),
                paragraph(right_value, styles["PassValue"]),
            ]
        )

    detail_table = Table(table_data, colWidths=[34 * mm, 52 * mm, 36 * mm, 50 * mm])
    detail_table.setStyle(
        TableStyle(
            [
                ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#1e293b")),
                ("INNERGRID", (0, 0), (-1, -1), 0.45, colors.HexColor("#cbd5e1")),
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eff6ff")),
                ("BACKGROUND", (2, 0), (2, -1), colors.HexColor("#eff6ff")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 7),
                ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )

    media_cells = [[qr_drawing(pass_qr_payload(visitor)), Paragraph("<b>QR Verification</b><br/>Scan to verify the key visitor details stored on this pass.", styles["PassValue"])]]
    photo_path = UPLOAD_FOLDER / str(visitor.get("photo_filename") or "")
    if visitor.get("photo_filename") and photo_path.exists():
        media_cells[0].append(Image(str(photo_path), width=34 * mm, height=34 * mm, kind="proportional"))
    else:
        media_cells[0].append(Paragraph("<b>Visitor photo</b><br/>Optional", styles["PassValue"]))

    media_table = Table(media_cells, colWidths=[44 * mm, 82 * mm, 46 * mm])
    media_table.setStyle(
        TableStyle(
            [
                ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#1e293b")),
                ("INNERGRID", (0, 0), (-1, -1), 0.45, colors.HexColor("#cbd5e1")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("ALIGN", (0, 0), (0, 0), "CENTER"),
                ("ALIGN", (2, 0), (2, 0), "CENTER"),
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#ffffff")),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )

    story = [
        header,
        Spacer(1, 10),
        detail_table,
        Spacer(1, 10),
        media_table,
        Spacer(1, 8),
        Paragraph("This pass is valid only for the visitor, flat, and time window shown above.", styles["PassSubtitle"]),
    ]
    doc.build(story)
    buffer.seek(0)
    return buffer


def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    return dict_row(
        """SELECT id, username, role, full_name, email, phone, flat_no, wing, tower_name,
                  account_status
           FROM users WHERE id = ?""",
        (user_id,),
    )


def dashboard_endpoint(role=None):
    role = role or session.get("role")
    if role == "owner":
        return "owner_dashboard"
    if role == "guard":
        return "guard_dashboard"
    return "user_dashboard"


def log_activity(cursor, action, details, actor_id=None, actor_role=None):
    actor_id = actor_id if actor_id is not None else session.get("user_id")
    actor_role = actor_role if actor_role is not None else session.get("role")
    cursor.execute(
        """INSERT INTO activity_logs (actor_id, actor_role, action, details)
           VALUES (?, ?, ?, ?)""",
        (actor_id, actor_role, action, details),
    )


def get_pending_registrations():
    return dict_rows(
        """SELECT id, username, full_name, email, phone, flat_no, tower_name,
                  aadhaar_number, account_status, email_verified, phone_verified,
                  created_at
           FROM pending_requests ORDER BY id DESC"""
    )


def get_residents(search=None):
    params = []
    where = ["role IN ('owner', 'user')", "account_status = 'approved'"]
    if search:
        term = f"%{search}%"
        where.append("(full_name LIKE ? OR username LIKE ? OR flat_no LIKE ? OR phone LIKE ?)")
        params.extend([term, term, term, term])
    return dict_rows(
        f"""SELECT id, username, COALESCE(NULLIF(full_name, ''), username) AS full_name,
                   role, email, phone, flat_no, wing, tower_name
            FROM users
            WHERE {' AND '.join(where)}
            ORDER BY tower_name, wing, flat_no, full_name""",
        params,
    )


def seed_demo_data(cursor):
    demo_users = [
        {
            "username": "owner@svms.local",
            "password": "owner123",
            "role": "owner",
            "full_name": "Priya Sharma",
            "email": "owner@svms.local",
            "phone": "9000000001",
            "flat_no": "A-101",
            "wing": "A",
            "floor_no": "1",
            "tower_name": "Sunrise Tower",
            "ownership_type": "Owner",
        },
        {
            "username": "guard@svms.local",
            "password": "guard123",
            "role": "guard",
            "full_name": "Raj Patel",
            "email": "guard@svms.local",
            "phone": "9000000002",
            "flat_no": "",
            "wing": "",
            "floor_no": "",
            "tower_name": "Main Gate",
            "ownership_type": "",
        },
        {
            "username": "user@svms.local",
            "password": "user123",
            "role": "user",
            "full_name": "Aman Mehta",
            "email": "user@svms.local",
            "phone": "9000000003",
            "flat_no": "B-204",
            "wing": "B",
            "floor_no": "2",
            "tower_name": "Maple Heights",
            "ownership_type": "Tenant",
        },
        {
            "username": "resident2@svms.local",
            "password": "user123",
            "role": "user",
            "full_name": "Neha Rao",
            "email": "resident2@svms.local",
            "phone": "9000000004",
            "flat_no": "C-308",
            "wing": "C",
            "floor_no": "3",
            "tower_name": "Cedar Block",
            "ownership_type": "Owner",
        },
    ]

    for user in demo_users:
        password_hash = generate_password_hash(user["password"])
        cursor.execute(
            """INSERT INTO users
               (username, password_hash, role, full_name, email, phone, flat_no, wing,
                floor_no, tower_name, ownership_type, account_status, email_verified,
                phone_verified, country, vehicle_count)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'approved', 1, 1, 'India', 0)
               ON CONFLICT(username) DO UPDATE SET
                   password_hash = excluded.password_hash,
                   role = excluded.role,
                   full_name = excluded.full_name,
                   email = excluded.email,
                   phone = excluded.phone,
                   flat_no = excluded.flat_no,
                   wing = excluded.wing,
                   floor_no = excluded.floor_no,
                   tower_name = excluded.tower_name,
                   ownership_type = excluded.ownership_type,
                   account_status = 'approved',
                   email_verified = 1,
                   phone_verified = 1,
                   updated_at = CURRENT_TIMESTAMP""",
            (
                user["username"],
                password_hash,
                user["role"],
                user["full_name"],
                user["email"],
                user["phone"],
                user["flat_no"],
                user["wing"],
                user["floor_no"],
                user["tower_name"],
                user["ownership_type"],
            ),
        )

    cursor.execute("SELECT id, username FROM users")
    user_ids = {username: user_id for user_id, username in cursor.fetchall()}
    flats = [
        ("A-101", "A", "1", "Sunrise Tower", user_ids.get("owner@svms.local")),
        ("B-204", "B", "2", "Maple Heights", user_ids.get("user@svms.local")),
        ("C-308", "C", "3", "Cedar Block", user_ids.get("resident2@svms.local")),
        ("D-1201", "D", "12", "Lake View", None),
    ]
    for flat_no, wing, floor_no, tower_name, owner_user_id in flats:
        cursor.execute(
            """INSERT INTO flats (flat_no, wing, floor_no, tower_name, owner_user_id, status)
               VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT(flat_no) DO UPDATE SET
                   wing = excluded.wing,
                   floor_no = excluded.floor_no,
                   tower_name = excluded.tower_name,
                   owner_user_id = COALESCE(excluded.owner_user_id, flats.owner_user_id),
                   status = excluded.status""",
            (flat_no, wing, floor_no, tower_name, owner_user_id, "occupied" if owner_user_id else "vacant"),
        )

    visitor_count = cursor.execute("SELECT COUNT(*) FROM visitor_requests").fetchone()[0]
    if visitor_count == 0:
        cursor.execute(
            """INSERT INTO visitor_requests
               (visitor_name, visitor_phone, purpose, flat_no, resident_id, resident_name,
                created_by_guard_id, status, token, vehicle_number, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                "Karan Delivery",
                "9876500011",
                "Grocery delivery",
                "B-204",
                user_ids.get("user@svms.local"),
                "Aman Mehta",
                user_ids.get("guard@svms.local"),
                "pending",
                None,
                "MH12AB1044",
                now_timestamp(),
                now_timestamp(),
            ),
        )
        cursor.execute(
            """INSERT INTO visitor_requests
               (visitor_name, visitor_phone, purpose, flat_no, resident_id, resident_name,
                created_by_guard_id, status, token, check_in_at, vehicle_number, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                "Meera Jain",
                "9876500022",
                "Family visit",
                "A-101",
                user_ids.get("owner@svms.local"),
                "Priya Sharma",
                user_ids.get("guard@svms.local"),
                "approved",
                generate_token(),
                now_timestamp(),
                "",
                now_timestamp(),
                now_timestamp(),
            ),
        )

    meeting_count = cursor.execute("SELECT COUNT(*) FROM meeting_requests").fetchone()[0]
    if meeting_count == 0:
        cursor.execute(
            """INSERT INTO meeting_requests
               (requester_id, target_user_id, purpose, requested_date, requested_time, status)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                user_ids.get("user@svms.local"),
                user_ids.get("owner@svms.local"),
                "Discuss parking allocation",
                datetime.now().strftime("%Y-%m-%d"),
                "18:30",
                "pending",
            ),
        )

    notice_count = cursor.execute("SELECT COUNT(*) FROM notices").fetchone()[0]
    if notice_count == 0:
        cursor.execute(
            """INSERT INTO notices (title, body, category, created_by)
               VALUES (?, ?, ?, ?)""",
            (
                "Gate 2 maintenance",
                "Gate 2 will remain closed from 10 AM to 2 PM. Please use the main gate.",
                "maintenance",
                user_ids.get("owner@svms.local"),
            ),
        )

    log_count = cursor.execute("SELECT COUNT(*) FROM activity_logs").fetchone()[0]
    if log_count == 0:
        cursor.execute(
            """INSERT INTO activity_logs (actor_id, actor_role, action, details)
               VALUES (?, ?, ?, ?)""",
            (user_ids.get("owner@svms.local"), "owner", "System ready", "Demo SVMS data initialized."),
        )


def check_otp_send_limit(channel, identity):
    now = int(time.time())
    window_start = now - OTP_SEND_WINDOW_SECONDS
    key = f"{channel}:{identity}"
    attempts = session.get("otp_send_attempts", {})
    recent_attempts = [
        int(sent_at)
        for sent_at in attempts.get(key, [])
        if int(sent_at) > window_start
    ]

    if len(recent_attempts) >= OTP_SEND_LIMIT:
        retry_after = OTP_SEND_WINDOW_SECONDS - (now - recent_attempts[0])
        attempts[key] = recent_attempts
        session["otp_send_attempts"] = attempts
        session.modified = True
        return False, max(1, retry_after), 0

    recent_attempts.append(now)
    attempts[key] = recent_attempts
    session["otp_send_attempts"] = attempts
    session.modified = True
    attempts_remaining = OTP_SEND_LIMIT - len(recent_attempts)
    next_retry_after = 0
    if attempts_remaining == 0:
        next_retry_after = OTP_SEND_WINDOW_SECONDS - (now - recent_attempts[0])
    return True, max(0, next_retry_after), attempts_remaining


@app.context_processor
def inject_otp_config():
    return {
        "email_otp_live": otp_service.is_email_configured(),
        "sms_otp_live": otp_service.is_sms_configured(),
    }


def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                full_name TEXT,
                profile_photo TEXT,
                dob TEXT,
                gender TEXT,
                email TEXT UNIQUE,
                email_verified BOOLEAN DEFAULT 0,
                phone TEXT,
                phone_verified BOOLEAN DEFAULT 0,
                alternate_phone TEXT,
                emergency_contact_name TEXT,
                emergency_contact_number TEXT,
                aadhaar_number TEXT,
                pan_number TEXT,
                id_document TEXT,
                flat_no TEXT,
                wing TEXT,
                floor_no TEXT,
                tower_name TEXT,
                ownership_type TEXT,
                move_in_date TEXT,
                address TEXT,
                city TEXT,
                state TEXT,
                pincode TEXT,
                country TEXT DEFAULT 'India',
                vehicle_count INTEGER DEFAULT 0,
                account_status TEXT DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        # table for pending registration requests that need guard/admin approval
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS pending_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                full_name TEXT,
                profile_photo TEXT,
                dob TEXT,
                gender TEXT,
                email TEXT,
                email_verified BOOLEAN DEFAULT 0,
                email_otp VARCHAR(6),
                phone TEXT,
                phone_verified BOOLEAN DEFAULT 0,
                phone_otp VARCHAR(6),
                alternate_phone TEXT,
                emergency_contact_name TEXT,
                emergency_contact_number TEXT,
                aadhaar_number TEXT,
                aadhaar_front TEXT,
                aadhaar_back TEXT,
                pan_number TEXT,
                id_document_type TEXT,
                id_document TEXT,
                selfie TEXT,
                flat_no TEXT,
                wing TEXT,
                floor_no TEXT,
                tower_name TEXT,
                ownership_type TEXT,
                move_in_date TEXT,
                num_family_members INTEGER,
                address TEXT,
                city TEXT,
                state TEXT,
                pincode TEXT,
                country TEXT DEFAULT 'India',
                vehicle_count INTEGER DEFAULT 0,
                security_question TEXT,
                security_answer TEXT,
                account_status TEXT DEFAULT 'pending',
                role TEXT NOT NULL DEFAULT 'user',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        # vehicles table for multi-vehicle support
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS vehicles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                vehicle_type TEXT,
                vehicle_number TEXT UNIQUE NOT NULL,
                brand TEXT,
                color TEXT,
                parking_slot TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS flats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                flat_no TEXT UNIQUE NOT NULL,
                wing TEXT,
                floor_no TEXT,
                tower_name TEXT,
                owner_user_id INTEGER,
                status TEXT DEFAULT 'occupied',
                notes TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(owner_user_id) REFERENCES users(id)
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS visitor_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                visitor_name TEXT NOT NULL,
                visitor_phone TEXT,
                purpose TEXT,
                flat_no TEXT,
                resident_id INTEGER,
                resident_name TEXT,
                created_by_guard_id INTEGER,
                status TEXT DEFAULT 'pending',
                token TEXT,
                check_in_at TIMESTAMP,
                check_out_at TIMESTAMP,
                id_proof TEXT,
                id_proof_number TEXT,
                photo_filename TEXT,
                vehicle_number TEXT,
                pass_generated_at TIMESTAMP,
                pass_valid_from TIMESTAMP,
                pass_valid_until TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(resident_id) REFERENCES users(id),
                FOREIGN KEY(created_by_guard_id) REFERENCES users(id)
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS meeting_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                requester_id INTEGER,
                target_user_id INTEGER,
                purpose TEXT NOT NULL,
                requested_date TEXT,
                requested_time TEXT,
                status TEXT DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(requester_id) REFERENCES users(id),
                FOREIGN KEY(target_user_id) REFERENCES users(id)
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS notices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                body TEXT,
                category TEXT DEFAULT 'general',
                created_by INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(created_by) REFERENCES users(id)
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS activity_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                actor_id INTEGER,
                actor_role TEXT,
                action TEXT NOT NULL,
                details TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(actor_id) REFERENCES users(id)
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS emergency_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                raised_by_guard_id INTEGER,
                message TEXT,
                status TEXT DEFAULT 'open',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(raised_by_guard_id) REFERENCES users(id)
            )
            """
        )
        conn.commit()
        migrate_existing_schema(cursor)
        conn.commit()
        # Seed example accounts and workflow records for development / testing.
        try:
            seed_demo_data(cursor)
            conn.commit()
        except Exception:
            # don't crash if seeding fails; DB may be locked in other contexts
            pass


def get_user(username):
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, password_hash, role FROM users WHERE username = ?", (username,))
        return cursor.fetchone()


def get_pending_requests():
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """SELECT id, username, full_name, email, phone, flat_no, tower_name,
               aadhaar_number, account_status, email_verified, phone_verified
               FROM pending_requests ORDER BY id DESC""")
        return cursor.fetchall()


def get_pending_request_by_username(username):
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM pending_requests WHERE username = ?", (username,))
        cols = [description[0] for description in cursor.description]
        row = cursor.fetchone()
        if row:
            return dict(zip(cols, row))
    return None


def get_pending_request_detail(req_id):
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM pending_requests WHERE id = ?", (req_id,))
        cols = [description[0] for description in cursor.description]
        row = cursor.fetchone()
        if row:
            return dict(zip(cols, row))
    return None


@app.route("/")
def home():
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = get_user(username)

        if user and user[2] and check_password_hash(user[2], password):
            session["user_id"] = user[0]
            session["username"] = user[1]
            session["role"] = user[3]
            flash("You have successfully logged in.", "success")
            if user[3] == "owner":
                return redirect(url_for("owner_dashboard"))
            if user[3] == "guard":
                return redirect(url_for("guard_dashboard"))
            # default to user dashboard for role 'user' or others
            return redirect(url_for("user_dashboard"))

        flash("Invalid username or password.", "danger")

    return render_template("login.html")


@app.route("/send_otp/email", methods=["POST"])
def send_email_otp():
    email = request.form.get("email", "").strip()
    if not email:
        return jsonify({"success": False, "message": "Email is required."}), 400
    allowed, retry_after, attempts_remaining = check_otp_send_limit("email", email.lower())
    if not allowed:
        return jsonify({
            "success": False,
            "message": f"OTP send limit reached. Try again in {format_wait(retry_after)}.",
            "retry_after": retry_after,
            "attempts_remaining": 0,
        }), 429

    otp = generate_otp()
    session["pending_email_otp"] = {"email": email, "otp": otp}
    session.pop("email_otp_verified", None)

    sent, message = otp_service.send_email_otp(email, otp)
    response = {
        "success": True,
        "message": message,
        "live": sent,
        "attempts_remaining": attempts_remaining,
        "retry_after": retry_after,
    }
    if not sent:
        response["demo_otp"] = otp
    return jsonify(response)


@app.route("/send_otp/phone", methods=["POST"])
def send_phone_otp():
    phone = request.form.get("phone", "").strip()
    if not phone or len(phone) != 10 or not phone.isdigit():
        return jsonify({"success": False, "message": "Valid 10-digit phone number is required."}), 400
    allowed, retry_after, attempts_remaining = check_otp_send_limit("phone", phone)
    if not allowed:
        return jsonify({
            "success": False,
            "message": f"OTP send limit reached. Try again in {format_wait(retry_after)}.",
            "retry_after": retry_after,
            "attempts_remaining": 0,
        }), 429

    otp = generate_otp()
    session["pending_phone_otp"] = {"phone": phone, "otp": otp}
    session.pop("phone_otp_verified", None)

    sent, message = otp_service.send_sms_otp(phone, otp)
    response = {
        "success": True,
        "message": message,
        "live": sent,
        "attempts_remaining": attempts_remaining,
        "retry_after": retry_after,
    }
    if not sent:
        response["demo_otp"] = otp
    return jsonify(response)


@app.route("/verify_otp/email", methods=["POST"])
def verify_email_otp():
    email = request.form.get("email", "").strip()
    otp = request.form.get("otp", "").strip()
    pending = session.get("pending_email_otp")
    if not pending or pending["email"] != email:
        return jsonify({"success": False, "message": "Please send OTP to this email first."}), 400
    if otp != pending["otp"]:
        return jsonify({"success": False, "message": "Invalid email OTP."}), 400
    session["email_otp_verified"] = email
    return jsonify({"success": True, "message": "Email verified successfully."})


@app.route("/verify_otp/phone", methods=["POST"])
def verify_phone_otp():
    phone = request.form.get("phone", "").strip()
    otp = request.form.get("otp", "").strip()
    pending = session.get("pending_phone_otp")
    if not pending or pending["phone"] != phone:
        return jsonify({"success": False, "message": "Please send OTP to this phone first."}), 400
    if otp != pending["otp"]:
        return jsonify({"success": False, "message": "Invalid phone OTP."}), 400
    session["phone_otp_verified"] = phone
    return jsonify({"success": True, "message": "Phone verified successfully."})


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm_pwd = request.form.get("confirm_password", "")
        
        # validate password match
        if password != confirm_pwd:
            flash("Passwords do not match.", "danger")
            return render_template("register.html")
        
        if not username or not password or len(password) < 6:
            flash("Username and password (min 6 chars) are required.", "danger")
            return render_template("register.html")
        
        # collect form data
        full_name = request.form.get("full_name", "").strip()
        dob = request.form.get("dob", "")
        gender = request.form.get("gender", "")
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()
        
        if session.get("email_otp_verified") != email:
            flash("Please verify your email with OTP before submitting.", "danger")
            return render_template("register.html")
        if session.get("phone_otp_verified") != phone:
            flash("Please verify your phone number with OTP before submitting.", "danger")
            return render_template("register.html")
        
        alternate_phone = request.form.get("alternate_phone", "").strip()
        emergency_contact_name = request.form.get("emergency_contact_name", "").strip()
        emergency_contact_number = request.form.get("emergency_contact_number", "").strip()
        
        # identity verification
        aadhaar_number = request.form.get("aadhaar_number", "").strip()
        pan_number = request.form.get("pan_number", "").strip()
        id_document_type = request.form.get("id_document_type", "").strip()
        
        # apartment info
        flat_no = request.form.get("flat_no", "").strip()
        wing = request.form.get("wing", "").strip()
        floor_no = request.form.get("floor_no", "").strip()
        tower_name = request.form.get("tower_name", "").strip()
        ownership_type = request.form.get("ownership_type", "")
        move_in_date = request.form.get("move_in_date", "")
        num_family_members = request.form.get("num_family_members", "1")
        
        # address
        address = request.form.get("address", "").strip()
        city = request.form.get("city", "").strip()
        state = request.form.get("state", "").strip()
        pincode = request.form.get("pincode", "").strip()
        
        # vehicle count
        vehicle_count = request.form.get("vehicle_count", "0")
        
        # security question
        security_question = request.form.get("security_question", "")
        security_answer = request.form.get("security_answer", "").strip()
        
        # handle file uploads
        uploaded_files = {
            'profile_photo': None,
            'aadhaar_front': None,
            'aadhaar_back': None,
            'id_document': None,
            'selfie': None
        }
        
        for field in uploaded_files:
            if field in request.files:
                file = request.files[field]
                if file and file.filename and allowed_file(file.filename):
                    filename = secure_filename(f"{username}_{field}_{file.filename}")
                    filepath = app.config['UPLOAD_FOLDER'] / filename
                    file.save(filepath)
                    uploaded_files[field] = filename
        
        profile_photo = uploaded_files['profile_photo']
        aadhaar_front = uploaded_files['aadhaar_front']
        aadhaar_back = uploaded_files['aadhaar_back']
        id_document = uploaded_files['id_document']
        selfie = uploaded_files['selfie']
        
        hashed_password = generate_password_hash(password)
        
        try:
            with sqlite3.connect(DB_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """INSERT INTO pending_requests 
                    (username, password_hash, full_name, profile_photo, dob, gender, email, phone,
                     alternate_phone, emergency_contact_name, emergency_contact_number, 
                     aadhaar_number, aadhaar_front, aadhaar_back, pan_number,
                     id_document_type, id_document, selfie, flat_no, wing, floor_no, tower_name, ownership_type, 
                     move_in_date, num_family_members, address, city, state, pincode, 
                     vehicle_count, security_question, security_answer, email_otp, phone_otp,
                     email_verified, phone_verified, role)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 1, ?)""",
                    (username, hashed_password, full_name, profile_photo, dob, gender, email, phone,
                     alternate_phone, emergency_contact_name, emergency_contact_number,
                     aadhaar_number, aadhaar_front, aadhaar_back, pan_number,
                     id_document_type, id_document, selfie, flat_no, wing, floor_no, tower_name, ownership_type,
                     move_in_date, num_family_members, address, city, state, pincode,
                     vehicle_count, security_question, security_answer,
                     session.get("pending_email_otp", {}).get("otp", ""),
                     session.get("pending_phone_otp", {}).get("otp", ""),
                     'user')
                )
                conn.commit()
            session.pop("pending_email_otp", None)
            session.pop("pending_phone_otp", None)
            session.pop("email_otp_verified", None)
            session.pop("phone_otp_verified", None)
            flash("Registration submitted successfully. Awaiting admin approval.", "info")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Username or email already exists.", "danger")
    
    return render_template("register.html")


@app.route("/owner-dashboard")
def owner_dashboard():
    if session.get("role") != "owner":
        return render_template("error.html", message="Access denied."), 403
    stats = {
        "owners": scalar("SELECT COUNT(*) FROM users WHERE role = 'owner'"),
        "guards": scalar("SELECT COUNT(*) FROM users WHERE role = 'guard'"),
        "residents": scalar("SELECT COUNT(*) FROM users WHERE role = 'user'"),
        "visitors": scalar("SELECT COUNT(*) FROM visitor_requests"),
        "pending_approvals": scalar("SELECT COUNT(*) FROM pending_requests"),
        "pending_visitors": scalar("SELECT COUNT(*) FROM visitor_requests WHERE status = 'pending'"),
        "meetings": scalar("SELECT COUNT(*) FROM meeting_requests"),
        "open_alerts": scalar("SELECT COUNT(*) FROM emergency_alerts WHERE status = 'open'"),
    }
    users = dict_rows(
        """SELECT id, username, role, COALESCE(NULLIF(full_name, ''), username) AS full_name,
                  email, phone, flat_no, tower_name, account_status
           FROM users ORDER BY role, full_name"""
    )
    visitor_requests = dict_rows(
        """SELECT vr.*, COALESCE(u.full_name, u.username, vr.resident_name) AS resident_full_name,
                  COALESCE(g.full_name, g.username, 'Gate desk') AS guard_name
           FROM visitor_requests vr
           LEFT JOIN users u ON u.id = vr.resident_id
           LEFT JOIN users g ON g.id = vr.created_by_guard_id
           ORDER BY vr.id DESC LIMIT 20"""
    )
    meeting_requests = dict_rows(
        """SELECT mr.*, COALESCE(r.full_name, r.username) AS requester_name,
                  COALESCE(t.full_name, t.username) AS target_name
           FROM meeting_requests mr
           LEFT JOIN users r ON r.id = mr.requester_id
           LEFT JOIN users t ON t.id = mr.target_user_id
           ORDER BY mr.id DESC LIMIT 20"""
    )
    flats = dict_rows(
        """SELECT f.*, COALESCE(u.full_name, u.username, 'Unassigned') AS owner_name
           FROM flats f
           LEFT JOIN users u ON u.id = f.owner_user_id
           ORDER BY f.tower_name, f.wing, f.flat_no"""
    )
    notices = dict_rows(
        """SELECT n.*, COALESCE(u.full_name, u.username, 'Admin') AS creator_name
           FROM notices n
           LEFT JOIN users u ON u.id = n.created_by
           ORDER BY n.id DESC LIMIT 8"""
    )
    logs = dict_rows(
        """SELECT al.*, COALESCE(u.full_name, u.username, 'System') AS actor_name
           FROM activity_logs al
           LEFT JOIN users u ON u.id = al.actor_id
           ORDER BY al.id DESC LIMIT 10"""
    )
    alerts = dict_rows(
        """SELECT ea.*, COALESCE(u.full_name, u.username, 'Guard') AS guard_name
           FROM emergency_alerts ea
           LEFT JOIN users u ON u.id = ea.raised_by_guard_id
           ORDER BY ea.id DESC LIMIT 5"""
    )
    return render_template(
        "owner_dashboard.html",
        username=session.get("username"),
        stats=stats,
        users=users,
        residents=get_residents(),
        pending_requests=get_pending_registrations(),
        visitor_requests=visitor_requests,
        meeting_requests=meeting_requests,
        flats=flats,
        notices=notices,
        logs=logs,
        alerts=alerts,
    )


@app.route("/guard-dashboard")
def guard_dashboard():
    if session.get("role") != "guard":
        return render_template("error.html", message="Access denied."), 403
    resident_search = request.args.get("resident_search", "").strip()
    pass_search = request.args.get("pass_search", "").strip().upper()
    visitor_requests = visitor_pass_query("1 = 1", limit=30)
    pass_where = "vr.status = 'approved'"
    pass_params = []
    if pass_search:
        pass_where += " AND UPPER(COALESCE(vr.token, '')) LIKE ?"
        pass_params.append(f"%{pass_search}%")
    pass_records = visitor_pass_query(pass_where, tuple(pass_params), limit=20)
    stats = {
        "pending": scalar("SELECT COUNT(*) FROM visitor_requests WHERE status = 'pending'"),
        "approved": scalar("SELECT COUNT(*) FROM visitor_requests WHERE status = 'approved'"),
        "checked_in": scalar("SELECT COUNT(*) FROM visitor_requests WHERE check_in_at IS NOT NULL AND check_out_at IS NULL"),
        "today": scalar("SELECT COUNT(*) FROM visitor_requests WHERE date(created_at) = date('now', 'localtime')"),
    }
    return render_template(
        "guard_dashboard.html",
        username=session.get("username"),
        stats=stats,
        residents=get_residents(resident_search),
        resident_search=resident_search,
        pass_search=pass_search,
        visitor_requests=visitor_requests,
        pass_records=pass_records,
        alerts=dict_rows("SELECT * FROM emergency_alerts ORDER BY id DESC LIMIT 4"),
    )


@app.route('/verify_registration/<username>', methods=['GET', 'POST'])
def verify_registration(username):
    req = get_pending_request_by_username(username)
    if not req:
        flash('Registration not found.', 'danger')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        email_otp = request.form.get('email_otp', '').strip()
        phone_otp = request.form.get('phone_otp', '').strip()
        
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT email_otp, phone_otp FROM pending_requests WHERE username = ?', (username,))
            row = cursor.fetchone()
            if not row:
                flash('Request not found.', 'danger')
                return redirect(url_for('login'))
            
            stored_email_otp, stored_phone_otp = row
            updates = []
            
            if email_otp and email_otp == stored_email_otp:
                updates.append('email_verified = 1')
            elif email_otp:
                flash('Invalid email OTP.', 'danger')
                return render_template('verify_registration.html', username=username)
            
            if phone_otp and phone_otp == stored_phone_otp:
                updates.append('phone_verified = 1')
            elif phone_otp:
                flash('Invalid phone OTP.', 'danger')
                return render_template('verify_registration.html', username=username)
            
            if updates:
                cursor.execute(f'UPDATE pending_requests SET {" , ".join(updates)} WHERE username = ?', (username,))
                conn.commit()
                flash('Verification successful. Awaiting admin approval.', 'success')
                return redirect(url_for('login'))
    
    return render_template('verify_registration.html', username=username, req=req)


@app.route('/request_detail/<int:req_id>')
def request_detail(req_id):
    if session.get('role') not in ['guard', 'owner']:
        return render_template('error.html', message='Access denied.'), 403
    req = get_pending_request_detail(req_id)
    if not req:
        flash('Request not found.', 'danger')
        return redirect(url_for('guard_dashboard'))
    return render_template('request_detail.html', req=req)


@app.route('/approve_request/<int:req_id>', methods=['POST'])
def approve_request(req_id):
    if session.get('role') != 'owner':
        return render_template('error.html', message='Access denied.'), 403
    
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        # get all fields from pending request
        cursor.execute("SELECT * FROM pending_requests WHERE id = ?", (req_id,))
        cols = [description[0] for description in cursor.description]
        row = cursor.fetchone()
        
        if not row:
            flash('Request not found.', 'danger')
            return redirect(url_for('guard_dashboard'))
        
        req_data = dict(zip(cols, row))
        
        try:
            user_fields = [
                'username', 'password_hash', 'role', 'full_name', 'profile_photo', 'dob', 'gender',
                'email', 'email_verified', 'phone', 'phone_verified', 'alternate_phone',
                'emergency_contact_name', 'emergency_contact_number', 'aadhaar_number', 'pan_number',
                'id_document', 'flat_no', 'wing', 'floor_no', 'tower_name', 'ownership_type', 'move_in_date',
                'address', 'city', 'state', 'pincode', 'country', 'vehicle_count', 'account_status'
            ]
            insert_vals = [
                req_data.get('username'),
                req_data.get('password_hash'),
                req_data.get('role', 'user'),
                req_data.get('full_name'),
                req_data.get('profile_photo'),
                req_data.get('dob'),
                req_data.get('gender'),
                req_data.get('email'),
                req_data.get('email_verified', 0),
                req_data.get('phone'),
                req_data.get('phone_verified', 0),
                req_data.get('alternate_phone'),
                req_data.get('emergency_contact_name'),
                req_data.get('emergency_contact_number'),
                req_data.get('aadhaar_number'),
                req_data.get('pan_number'),
                req_data.get('id_document'),
                req_data.get('flat_no'),
                req_data.get('wing'),
                req_data.get('floor_no'),
                req_data.get('tower_name'),
                req_data.get('ownership_type'),
                req_data.get('move_in_date'),
                req_data.get('address'),
                req_data.get('city'),
                req_data.get('state'),
                req_data.get('pincode'),
                req_data.get('country', 'India'),
                req_data.get('vehicle_count', 0),
                'approved',
            ]
            placeholders = ', '.join(['?' for _ in user_fields])
            cols_str = ', '.join(user_fields)
            
            cursor.execute(
                f"INSERT OR IGNORE INTO users ({cols_str}) VALUES ({placeholders})",
                insert_vals
            )
            if req_data.get('flat_no'):
                cursor.execute(
                    """INSERT INTO flats (flat_no, wing, floor_no, tower_name, owner_user_id, status)
                       SELECT ?, ?, ?, ?, id, 'occupied' FROM users WHERE username = ?
                       ON CONFLICT(flat_no) DO UPDATE SET
                           wing = excluded.wing,
                           floor_no = excluded.floor_no,
                           tower_name = excluded.tower_name,
                           owner_user_id = excluded.owner_user_id,
                           status = 'occupied'""",
                    (
                        req_data.get('flat_no'),
                        req_data.get('wing'),
                        req_data.get('floor_no'),
                        req_data.get('tower_name'),
                        req_data.get('username'),
                    ),
                )
            cursor.execute('DELETE FROM pending_requests WHERE id = ?', (req_id,))
            log_activity(cursor, "Approved registration", f'Approved {req_data["username"]}.')
            conn.commit()
            flash(f'Approved {req_data["username"]}. Account created.', 'success')
        except Exception as e:
            flash(f'Failed to approve request: {str(e)}', 'danger')
    
    return redirect(url_for('owner_dashboard'))


@app.route('/reject_request/<int:req_id>', methods=['POST'])
def reject_request(req_id):
    if session.get('role') != 'owner':
        return render_template('error.html', message='Access denied.'), 403
    
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT username FROM pending_requests WHERE id = ?', (req_id,))
        row = cursor.fetchone()
        if not row:
            flash('Request not found.', 'danger')
            return redirect(url_for('guard_dashboard'))
        
        username = row[0]
        cursor.execute('DELETE FROM pending_requests WHERE id = ?', (req_id,))
        log_activity(cursor, "Rejected registration", f"Rejected {username}.")
        conn.commit()
        flash(f'Request from {username} rejected.', 'info')
    
    return redirect(url_for('owner_dashboard'))


@app.route('/user-dashboard')
def user_dashboard():
    if session.get('role') != 'user':
        return render_template('error.html', message='Access denied.'), 403
    user_id = session.get("user_id")
    visitor_requests = dict_rows(
        """SELECT vr.*, COALESCE(g.full_name, g.username, 'Gate desk') AS guard_name
           FROM visitor_requests vr
           LEFT JOIN users g ON g.id = vr.created_by_guard_id
           WHERE vr.resident_id = ?
           ORDER BY vr.id DESC""",
        (user_id,),
    )
    incoming_meetings = dict_rows(
        """SELECT mr.*, COALESCE(u.full_name, u.username) AS requester_name,
                  COALESCE(u.flat_no, '') AS requester_flat
           FROM meeting_requests mr
           LEFT JOIN users u ON u.id = mr.requester_id
           WHERE mr.target_user_id = ?
           ORDER BY mr.id DESC""",
        (user_id,),
    )
    outgoing_meetings = dict_rows(
        """SELECT mr.*, COALESCE(u.full_name, u.username) AS target_name,
                  COALESCE(u.flat_no, '') AS target_flat
           FROM meeting_requests mr
           LEFT JOIN users u ON u.id = mr.target_user_id
           WHERE mr.requester_id = ?
           ORDER BY mr.id DESC""",
        (user_id,),
    )
    stats = {
        "pending_visitors": sum(1 for item in visitor_requests if item["status"] == "pending"),
        "approved_visitors": sum(1 for item in visitor_requests if item["status"] == "approved"),
        "history": sum(1 for item in visitor_requests if item["check_out_at"]),
        "meetings": len(incoming_meetings) + len(outgoing_meetings),
    }
    return render_template(
        'user_dashboard.html',
        username=session.get('username'),
        user=current_user(),
        stats=stats,
        visitor_requests=visitor_requests,
        incoming_meetings=incoming_meetings,
        outgoing_meetings=outgoing_meetings,
        residents=[resident for resident in get_residents() if resident["id"] != user_id],
        notices=dict_rows("SELECT * FROM notices ORDER BY id DESC LIMIT 5"),
    )


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")
        if not username or len(new_password) < 6 or new_password != confirm_password:
            flash("Enter a valid username and matching password of at least 6 characters.", "danger")
            return render_template("forgot_password.html")
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
            if not cursor.fetchone():
                flash("No account found for that username.", "danger")
                return render_template("forgot_password.html")
            cursor.execute(
                "UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE username = ?",
                (generate_password_hash(new_password), username),
            )
            conn.commit()
        flash("Password updated. You can sign in now.", "success")
        return redirect(url_for("login"))
    return render_template("forgot_password.html")


@app.route("/profile", methods=["GET", "POST"])
def profile():
    if not session.get("user_id"):
        return redirect(url_for("login"))
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()
        flat_no = request.form.get("flat_no", "").strip()
        wing = request.form.get("wing", "").strip()
        tower_name = request.form.get("tower_name", "").strip()
        try:
            with sqlite3.connect(DB_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """UPDATE users
                       SET full_name = ?, email = ?, phone = ?, flat_no = ?, wing = ?,
                           tower_name = ?, updated_at = CURRENT_TIMESTAMP
                       WHERE id = ?""",
                    (full_name, email, phone, flat_no, wing, tower_name, session["user_id"]),
                )
                if flat_no and session.get("role") != "guard":
                    cursor.execute(
                        """INSERT INTO flats (flat_no, wing, tower_name, owner_user_id, status)
                           VALUES (?, ?, ?, ?, 'occupied')
                           ON CONFLICT(flat_no) DO UPDATE SET
                               wing = excluded.wing,
                               tower_name = excluded.tower_name,
                               owner_user_id = excluded.owner_user_id,
                               status = 'occupied'""",
                        (flat_no, wing, tower_name, session["user_id"]),
                    )
                log_activity(cursor, "Updated profile", "Profile information changed.")
                conn.commit()
            flash("Profile updated.", "success")
            return redirect(url_for("profile"))
        except sqlite3.IntegrityError:
            flash("That email is already used by another account.", "danger")
    return render_template("profile.html", user=current_user())


@app.route("/guard/visitors/add", methods=["POST"])
def add_visitor_request():
    if session.get("role") != "guard":
        return render_template("error.html", message="Access denied."), 403
    visitor_name = request.form.get("visitor_name", "").strip()
    visitor_phone = request.form.get("visitor_phone", "").strip()
    purpose = request.form.get("purpose", "").strip()
    resident_id = request.form.get("resident_id", "").strip()
    vehicle_number = request.form.get("vehicle_number", "").strip().upper()
    id_proof_number = request.form.get("id_proof_number", "").strip().upper()
    if not visitor_name or not resident_id:
        flash("Visitor name and resident are required.", "danger")
        return redirect(url_for("guard_dashboard"))

    resident = dict_row(
        """SELECT id, full_name, username, flat_no FROM users
           WHERE id = ? AND role IN ('owner', 'user') AND account_status = 'approved'""",
        (resident_id,),
    )
    if not resident:
        flash("Selected resident was not found.", "danger")
        return redirect(url_for("guard_dashboard"))

    id_proof = None
    file = request.files.get("id_proof")
    if file and file.filename and allowed_file(file.filename):
        filename = secure_filename(f"visitor_{int(time.time())}_{file.filename}")
        file.save(app.config["UPLOAD_FOLDER"] / filename)
        id_proof = filename

    photo_filename = None
    photo = request.files.get("visitor_photo")
    if photo and photo.filename and allowed_file(photo.filename):
        photo_filename = secure_filename(f"visitor_photo_{int(time.time())}_{photo.filename}")
        photo.save(app.config["UPLOAD_FOLDER"] / photo_filename)

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """INSERT INTO visitor_requests
               (visitor_name, visitor_phone, purpose, flat_no, resident_id, resident_name,
                created_by_guard_id, status, id_proof, id_proof_number, photo_filename, vehicle_number)
               VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?)""",
            (
                visitor_name,
                visitor_phone,
                purpose,
                resident.get("flat_no"),
                resident["id"],
                resident.get("full_name") or resident.get("username"),
                session.get("user_id"),
                id_proof,
                id_proof_number,
                photo_filename,
                vehicle_number,
            ),
        )
        log_activity(cursor, "Visitor request created", f"{visitor_name} requested for flat {resident.get('flat_no')}.")
        conn.commit()
    flash("Visitor request sent to the resident.", "success")
    return redirect(url_for("guard_dashboard"))


@app.route("/visitor/<int:visitor_id>/decision", methods=["POST"])
def decide_visitor(visitor_id):
    if session.get("role") not in ["owner", "user"]:
        return render_template("error.html", message="Access denied."), 403
    action = request.form.get("action", "")
    if action not in ["approved", "rejected"]:
        flash("Invalid visitor decision.", "danger")
        return redirect(url_for(dashboard_endpoint()))
    visitor = dict_row("SELECT * FROM visitor_requests WHERE id = ?", (visitor_id,))
    if not visitor:
        flash("Visitor request not found.", "danger")
        return redirect(url_for(dashboard_endpoint()))
    if session.get("role") != "owner" and visitor["resident_id"] != session.get("user_id"):
        return render_template("error.html", message="Access denied."), 403
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        token = visitor.get("token")
        if action == "approved" and not token:
            token = generate_unique_pass_id(cursor)
        cursor.execute(
            """UPDATE visitor_requests
               SET status = ?, token = ?, updated_at = CURRENT_TIMESTAMP
               WHERE id = ?""",
            (action, token, visitor_id),
        )
        log_activity(cursor, f"Visitor {action}", f'{visitor["visitor_name"]} marked {action}.')
        conn.commit()
    flash(f"Visitor request {action}.", "success" if action == "approved" else "info")
    return redirect(url_for(dashboard_endpoint()))


@app.route("/guard/visitor/<int:visitor_id>/generate-pass", methods=["POST"])
def generate_visitor_pass(visitor_id):
    if session.get("role") != "guard":
        return render_template("error.html", message="Access denied."), 403
    visitor = get_visitor_pass(visitor_id)
    if not visitor or visitor.get("status") != "approved":
        flash("Visitor pass can be generated only after approval.", "danger")
        return redirect(url_for("guard_dashboard") + "#movement")
    if visitor.get("check_out_at"):
        flash("Checked-out visitors cannot receive a new pass.", "danger")
        return redirect(url_for("guard_dashboard") + "#movement")

    has_active_pass = (
        visitor.get("pass_generated_at")
        and visitor.get("pass_valid_from")
        and visitor.get("pass_valid_until")
        and not visitor.get("pass_is_expired")
    )
    if has_active_pass:
        flash("Visitor pass is already active.", "info")
        return redirect(url_for("guard_dashboard") + "#movement")

    valid_from = datetime.now()
    valid_until = valid_from + timedelta(hours=PASS_VALIDITY_HOURS)
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        pass_id = visitor.get("token") or generate_unique_pass_id(cursor)
        cursor.execute(
            """UPDATE visitor_requests
               SET token = ?, pass_generated_at = ?, pass_valid_from = ?, pass_valid_until = ?,
                   updated_at = CURRENT_TIMESTAMP
               WHERE id = ?""",
            (
                pass_id,
                valid_from.strftime("%Y-%m-%d %H:%M:%S"),
                valid_from.strftime("%Y-%m-%d %H:%M:%S"),
                valid_until.strftime("%Y-%m-%d %H:%M:%S"),
                visitor_id,
            ),
        )
        log_activity(cursor, "Visitor pass generated", f'{visitor["visitor_name"]} received pass {pass_id}.')
        conn.commit()
    flash("Visitor pass generated.", "success")
    return redirect(url_for("guard_dashboard") + "#movement")


@app.route("/guard/visitor/<int:visitor_id>/pass")
def view_visitor_pass(visitor_id):
    if session.get("role") != "guard":
        return render_template("error.html", message="Access denied."), 403
    visitor = get_visitor_pass(visitor_id)
    if not visitor or visitor.get("status") != "approved":
        flash("Visitor pass is available only for approved visitors.", "danger")
        return redirect(url_for("guard_dashboard") + "#movement")
    if not visitor.get("pass_generated_at"):
        flash("Generate the visitor pass before viewing it.", "warning")
        return redirect(url_for("guard_dashboard") + "#movement")
    return render_template("visitor_pass.html", visitor=visitor, society_name=SOCIETY_NAME)


@app.route("/guard/visitor/<int:visitor_id>/pass.pdf")
def visitor_pass_pdf(visitor_id):
    if session.get("role") != "guard":
        return render_template("error.html", message="Access denied."), 403
    visitor = get_visitor_pass(visitor_id)
    if not visitor or visitor.get("status") != "approved":
        return render_template("error.html", message="Visitor pass is available only for approved visitors."), 404
    if not visitor.get("pass_generated_at"):
        return render_template("error.html", message="Generate the visitor pass before opening the PDF."), 400
    pdf_buffer = build_visitor_pass_pdf(visitor)
    pass_id = visitor.get("token") or f"visitor-{visitor_id}"
    return send_file(
        pdf_buffer,
        mimetype="application/pdf",
        as_attachment=request.args.get("download") == "1",
        download_name=f"{pass_id}-visitor-pass.pdf",
    )


@app.route("/guard/visitor/<int:visitor_id>/check-in", methods=["POST"])
def check_in_visitor(visitor_id):
    if session.get("role") != "guard":
        return render_template("error.html", message="Access denied."), 403
    visitor = dict_row("SELECT * FROM visitor_requests WHERE id = ?", (visitor_id,))
    if not visitor or visitor["status"] != "approved":
        flash("Only approved visitors can be checked in.", "danger")
        return redirect(url_for("guard_dashboard"))
    if not visitor.get("pass_generated_at"):
        flash("Generate the visitor pass before check-in.", "warning")
        return redirect(url_for("guard_dashboard") + "#movement")
    if is_pass_expired(visitor):
        flash("Visitor pass has expired. Generate a new pass before check-in.", "danger")
        return redirect(url_for("guard_dashboard") + "#movement")
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """UPDATE visitor_requests
               SET check_in_at = COALESCE(check_in_at, CURRENT_TIMESTAMP),
                   updated_at = CURRENT_TIMESTAMP
               WHERE id = ?""",
            (visitor_id,),
        )
        log_activity(cursor, "Visitor checked in", f'{visitor["visitor_name"]} entered the society.')
        conn.commit()
    flash("Visitor checked in.", "success")
    return redirect(url_for("guard_dashboard"))


@app.route("/guard/visitor/<int:visitor_id>/check-out", methods=["POST"])
def check_out_visitor(visitor_id):
    if session.get("role") != "guard":
        return render_template("error.html", message="Access denied."), 403
    visitor = dict_row("SELECT * FROM visitor_requests WHERE id = ?", (visitor_id,))
    if not visitor or not visitor["check_in_at"]:
        flash("Check-in is required before check-out.", "danger")
        return redirect(url_for("guard_dashboard"))
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """UPDATE visitor_requests
               SET check_out_at = COALESCE(check_out_at, CURRENT_TIMESTAMP),
                   updated_at = CURRENT_TIMESTAMP
               WHERE id = ?""",
            (visitor_id,),
        )
        log_activity(cursor, "Visitor checked out", f'{visitor["visitor_name"]} exited the society.')
        conn.commit()
    flash("Visitor checked out.", "success")
    return redirect(url_for("guard_dashboard"))


@app.route("/guard/emergency-alert", methods=["POST"])
def emergency_alert():
    if session.get("role") != "guard":
        return render_template("error.html", message="Access denied."), 403
    message = request.form.get("message", "").strip() or "Emergency assistance required at the gate."
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO emergency_alerts (raised_by_guard_id, message) VALUES (?, ?)",
            (session.get("user_id"), message),
        )
        cursor.execute(
            """INSERT INTO notices (title, body, category, created_by)
               VALUES (?, ?, 'alert', ?)""",
            ("Emergency alert", message, session.get("user_id")),
        )
        log_activity(cursor, "Emergency alert raised", message)
        conn.commit()
    flash("Emergency alert raised for admin review.", "warning")
    return redirect(url_for("guard_dashboard"))


@app.route("/meetings/add", methods=["POST"])
def add_meeting_request():
    if session.get("role") not in ["owner", "user"]:
        return render_template("error.html", message="Access denied."), 403
    target_user_id = request.form.get("target_user_id", "").strip()
    purpose = request.form.get("purpose", "").strip()
    requested_date = request.form.get("requested_date", "").strip()
    requested_time = request.form.get("requested_time", "").strip()
    if not target_user_id or not purpose:
        flash("Select a resident and enter the meeting purpose.", "danger")
        return redirect(url_for(dashboard_endpoint()))
    if str(session.get("user_id")) == target_user_id:
        flash("Choose another resident for the meeting request.", "danger")
        return redirect(url_for(dashboard_endpoint()))
    target = dict_row("SELECT id FROM users WHERE id = ? AND role IN ('owner', 'user')", (target_user_id,))
    if not target:
        flash("Target resident was not found.", "danger")
        return redirect(url_for(dashboard_endpoint()))
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """INSERT INTO meeting_requests
               (requester_id, target_user_id, purpose, requested_date, requested_time, status)
               VALUES (?, ?, ?, ?, ?, 'pending')""",
            (session.get("user_id"), target_user_id, purpose, requested_date, requested_time),
        )
        log_activity(cursor, "Meeting requested", purpose)
        conn.commit()
    flash("Meeting request sent.", "success")
    return redirect(url_for(dashboard_endpoint()))


@app.route("/meeting/<int:meeting_id>/decision", methods=["POST"])
def decide_meeting(meeting_id):
    if session.get("role") not in ["owner", "user"]:
        return render_template("error.html", message="Access denied."), 403
    action = request.form.get("action", "")
    if action not in ["approved", "rejected"]:
        flash("Invalid meeting decision.", "danger")
        return redirect(url_for(dashboard_endpoint()))
    meeting = dict_row("SELECT * FROM meeting_requests WHERE id = ?", (meeting_id,))
    if not meeting:
        flash("Meeting request not found.", "danger")
        return redirect(url_for(dashboard_endpoint()))
    if session.get("role") != "owner" and meeting["target_user_id"] != session.get("user_id"):
        return render_template("error.html", message="Access denied."), 403
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE meeting_requests SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (action, meeting_id),
        )
        log_activity(cursor, f"Meeting {action}", meeting.get("purpose", "Meeting request updated."))
        conn.commit()
    flash(f"Meeting request {action}.", "success" if action == "approved" else "info")
    return redirect(url_for(dashboard_endpoint()))


@app.route("/owner/users/add", methods=["POST"])
def owner_add_user():
    if session.get("role") != "owner":
        return render_template("error.html", message="Access denied."), 403
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    role = request.form.get("role", "user")
    if role not in ["owner", "guard", "user"] or not username or len(password) < 6:
        flash("Enter a username, valid role, and password of at least 6 characters.", "danger")
        return redirect(url_for("owner_dashboard"))
    full_name = request.form.get("full_name", "").strip()
    email = request.form.get("email", "").strip()
    phone = request.form.get("phone", "").strip()
    flat_no = request.form.get("flat_no", "").strip()
    wing = request.form.get("wing", "").strip()
    tower_name = request.form.get("tower_name", "").strip()
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """INSERT INTO users
                   (username, password_hash, role, full_name, email, phone, flat_no, wing,
                    tower_name, account_status, email_verified, phone_verified)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'approved', 1, 1)""",
                (username, generate_password_hash(password), role, full_name, email, phone, flat_no, wing, tower_name),
            )
            new_user_id = cursor.lastrowid
            if flat_no and role != "guard":
                cursor.execute(
                    """INSERT INTO flats (flat_no, wing, tower_name, owner_user_id, status)
                       VALUES (?, ?, ?, ?, 'occupied')
                       ON CONFLICT(flat_no) DO UPDATE SET
                           wing = excluded.wing,
                           tower_name = excluded.tower_name,
                           owner_user_id = excluded.owner_user_id,
                           status = 'occupied'""",
                    (flat_no, wing, tower_name, new_user_id),
                )
            role_label = "admin" if role == "owner" else role
            log_activity(cursor, "User added", f"{username} added as {role_label}.")
            conn.commit()
        flash("User added successfully.", "success")
    except sqlite3.IntegrityError:
        flash("Username or email already exists.", "danger")
    return redirect(url_for("owner_dashboard"))


@app.route("/owner/users/<int:user_id>/delete", methods=["POST"])
def owner_delete_user(user_id):
    if session.get("role") != "owner":
        return render_template("error.html", message="Access denied."), 403
    if user_id == session.get("user_id"):
        flash("You cannot delete your own admin account.", "danger")
        return redirect(url_for("owner_dashboard"))
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,))
        row = cursor.fetchone()
        if not row:
            flash("User not found.", "danger")
            return redirect(url_for("owner_dashboard"))
        cursor.execute("UPDATE flats SET owner_user_id = NULL, status = 'vacant' WHERE owner_user_id = ?", (user_id,))
        cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
        log_activity(cursor, "User deleted", f"{row[0]} removed from SVMS.")
        conn.commit()
    flash("User deleted.", "info")
    return redirect(url_for("owner_dashboard"))


@app.route("/owner/users/<int:user_id>/reset-password", methods=["POST"])
def owner_reset_password(user_id):
    if session.get("role") != "owner":
        return render_template("error.html", message="Access denied."), 403
    new_password = request.form.get("new_password", "")
    if len(new_password) < 6:
        flash("Password must be at least 6 characters.", "danger")
        return redirect(url_for("owner_dashboard"))
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (generate_password_hash(new_password), user_id),
        )
        log_activity(cursor, "Password reset", f"Password reset for user #{user_id}.")
        conn.commit()
    flash("Password reset successfully.", "success")
    return redirect(url_for("owner_dashboard"))


@app.route("/owner/flats/add", methods=["POST"])
def owner_add_flat():
    if session.get("role") != "owner":
        return render_template("error.html", message="Access denied."), 403
    flat_no = request.form.get("flat_no", "").strip()
    if not flat_no:
        flash("Flat number is required.", "danger")
        return redirect(url_for("owner_dashboard"))
    wing = request.form.get("wing", "").strip()
    floor_no = request.form.get("floor_no", "").strip()
    tower_name = request.form.get("tower_name", "").strip()
    owner_user_id = request.form.get("owner_user_id") or None
    status = "occupied" if owner_user_id else request.form.get("status", "vacant")
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """INSERT INTO flats (flat_no, wing, floor_no, tower_name, owner_user_id, status)
               VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT(flat_no) DO UPDATE SET
                   wing = excluded.wing,
                   floor_no = excluded.floor_no,
                   tower_name = excluded.tower_name,
                   owner_user_id = excluded.owner_user_id,
                   status = excluded.status""",
            (flat_no, wing, floor_no, tower_name, owner_user_id, status),
        )
        log_activity(cursor, "Flat saved", f"{flat_no} saved in flat registry.")
        conn.commit()
    flash("Flat saved.", "success")
    return redirect(url_for("owner_dashboard"))


@app.route("/owner/notices/add", methods=["POST"])
def owner_add_notice():
    if session.get("role") != "owner":
        return render_template("error.html", message="Access denied."), 403
    title = request.form.get("title", "").strip()
    body = request.form.get("body", "").strip()
    category = request.form.get("category", "general")
    if not title:
        flash("Notice title is required.", "danger")
        return redirect(url_for("owner_dashboard"))
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO notices (title, body, category, created_by) VALUES (?, ?, ?, ?)",
            (title, body, category, session.get("user_id")),
        )
        log_activity(cursor, "Notice posted", title)
        conn.commit()
    flash("Notice posted.", "success")
    return redirect(url_for("owner_dashboard"))


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


@app.errorhandler(404)
def page_not_found(error):
    return render_template("error.html", message="Page not found."), 404


init_db()



if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
