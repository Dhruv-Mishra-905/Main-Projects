"""OTP delivery — email via Gmail SMTP (free) and optional SMS via Fast2SMS (India free credits)."""
import json
import os
import smtplib
import ssl
import urllib.error
import urllib.parse
import urllib.request
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


def _env(key, default=""):
    return os.environ.get(key, default).strip()


def is_email_configured():
    return bool(_env("SMTP_USER") and _env("SMTP_PASSWORD"))


def is_sms_configured():
    return bool(_env("FAST2SMS_API_KEY"))


def send_email_otp(to_email, otp):
    """Send OTP email. Returns (success, message). Uses Gmail SMTP when configured."""
    if not is_email_configured():
        return False, "Email SMTP not configured — using demo mode."

    smtp_host = _env("SMTP_HOST", "smtp.gmail.com")
    smtp_port = int(_env("SMTP_PORT", "587"))
    smtp_user = _env("SMTP_USER")
    smtp_pass = _env("SMTP_PASSWORD")
    if "gmail.com" in smtp_host.lower():
        smtp_pass = smtp_pass.replace(" ", "")
    smtp_from = _env("SMTP_FROM", smtp_user)

    subject = "SVMS — Your Verification Code"
    body = f"""Hello,

Your Society Visitor Management System verification code is:

    {otp}

This code expires in 10 minutes. Do not share it with anyone.

— SVMS Team"""

    msg = MIMEMultipart()
    msg["From"] = smtp_from
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as server:
            server.starttls(context=context)
            server.login(smtp_user, smtp_pass)
            server.sendmail(smtp_from, to_email, msg.as_string())
        return True, f"OTP sent to {to_email}. Check your inbox."
    except Exception as exc:
        return False, f"Failed to send email: {exc}"


def send_sms_otp(phone, otp):
    """Send OTP SMS via Fast2SMS (free credits on signup). Returns (success, message)."""
    api_key = _env("FAST2SMS_API_KEY")
    if not api_key:
        return False, "SMS API not configured — using demo mode."

    payload = urllib.parse.urlencode({
        "route": "otp",
        "variables_values": otp,
        "numbers": phone,
    }).encode("utf-8")

    req = urllib.request.Request(
        "https://www.fast2sms.com/dev/bulkV2",
        data=payload,
        method="POST",
        headers={
            "authorization": api_key,
            "accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = resp.read().decode("utf-8")
        try:
            result = json.loads(data)
        except json.JSONDecodeError:
            result = {}
        if result.get("return") is True or '"return":true' in data.replace(" ", ""):
            return True, f"OTP sent to +91{phone}."
        return False, f"SMS provider error: {data[:120]}"
    except urllib.error.HTTPError as exc:
        return False, f"SMS failed (HTTP {exc.code})."
    except Exception as exc:
        return False, f"SMS failed: {exc}"
