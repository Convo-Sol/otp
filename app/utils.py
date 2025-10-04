import smtplib
import ssl
import os
import uuid
import bcrypt

from dotenv import load_dotenv
from supabase import Client, create_client

load_dotenv()

SMTP_HOST = os.getenv("SMTP_HOST")
SMTP_PORT = int(os.getenv("SMTP_PORT"))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")

# Supabase configuration
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_ANON_KEY")

# ✅ Initialize client properly
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

def hash_password(password: str) -> str:
    """Hash a password using bcrypt"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def is_valid_bcrypt_hash(hashed: str) -> bool:
    """Check if the string is a valid bcrypt hash"""
    return hashed.startswith(('$2a$', '$2b$', '$2y$')) and len(hashed) == 60

def verify_password(password: str, hashed: str) -> bool:
    """Verify a password against its hash"""
    if not is_valid_bcrypt_hash(hashed):
        return False
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def send_email(to_email: str, otp: str):
    """Send OTP via SMTP"""
    context = ssl.create_default_context()
    message = f"""\
Subject: Your OTP Code

Your OTP code is: {otp}
This code will expire in 5 minutes."""

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
        server.starttls(context=context)
        server.login(SMTP_USER, SMTP_PASSWORD)
        server.sendmail(SMTP_USER, to_email, message)
