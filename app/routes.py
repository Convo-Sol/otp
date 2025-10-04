from flask import Blueprint, request, jsonify
from datetime import datetime, timedelta
import random
import uuid
from .utils import send_email, supabase, hash_password, verify_password, is_valid_bcrypt_hash

bp = Blueprint("otp", __name__)  # <--- THIS is what __init__.py imports

# In-memory OTP store
otp_store = {}

@bp.route("/request-otp", methods=["POST"])
def request_otp():
    data = request.get_json()
    email = data["email"]
    otp = str(random.randint(100000, 999999))  # 6-digit OTP
    expires_at = datetime.utcnow() + timedelta(seconds=300)  # 5 minutes

    otp_store[email] = {"otp": otp, "expires_at": expires_at}

    try:
        send_email(email, otp)
    except Exception as e:
        return jsonify({"error": f"Failed to send OTP: {str(e)}"}), 500

    return jsonify({"message": "OTP sent to email"})

@bp.route("/verify-otp", methods=["POST"])
def verify_otp():
    data = request.get_json()
    email = data["email"]
    otp = data["otp"]
    record = otp_store.get(email)

    if not record:
        return jsonify({"error": "No OTP requested for this email"}), 400
    if datetime.utcnow() > record["expires_at"]:
        return jsonify({"error": "OTP expired"}), 400
    if otp != record["otp"]:
        return jsonify({"error": "Invalid OTP"}), 400

    del otp_store[email]  # OTP verified → delete to prevent reuse

    # Check if user already exists
    try:
        existing_user = supabase.table('app_users').select('id, password').eq('email', email).execute()
        is_new_user = not existing_user.data
    except Exception as e:
        return jsonify({"error": f"Error checking existing user: {str(e)}"}), 500

    # If user exists and already has a password hash, they can still login via OTP.
    # We do not block OTP login based on password status.

    if is_new_user:
        # Insert new user
        user_id = str(uuid.uuid4())
        temp_password = "temp_password"  # Placeholder (plain text)
        insert_data = {
            'id': user_id,
            'email': email,
            'username': email,
            'user_type': 'business',
            'password': temp_password,
            'is_active': True
        }
        try:
            supabase.table('app_users').insert(insert_data).execute()
        except Exception as e:
            return jsonify({"error": f"Error inserting new user: {str(e)}"}), 500

    return jsonify({"message": "OTP verified", "is_new_user": is_new_user})

@bp.route("/login-password", methods=["POST"])
def login_password():
    data = request.get_json()
    email = data["email"]
    password = data["password"]

    # Check if user exists and get user_type and password
    user = supabase.table('app_users').select('id, password, user_type').eq('email', email).execute()
    if not user.data:
        return jsonify({"error": "No account found. Please sign up with Email + OTP."}), 400

    user_data = user.data[0]

    # Check if user_type is business, else reject login
    if user_data.get('user_type') != 'business':
        return jsonify({"error": "This portal is for business users only. Admin login is not allowed here."}), 403

    # Verify password (stored as plain text)
    if not user_data.get('password'):
        return jsonify({"error": "Password not set. Please reset your password."}), 400
    if password != user_data['password']:
        return jsonify({"error": "Invalid email or password"}), 400

    return jsonify({"message": "Login successful"})

@bp.route("/admin-login", methods=["POST"])
def admin_login():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")

    print(f"DEBUG: Admin login attempt for email: {email}")

    # Check if user exists and get user_type and password
    try:
        user = supabase.table('app_users').select('id, password, user_type').eq('email', email).execute()
        print(f"DEBUG: Query result: {user}")
        print(f"DEBUG: User data: {user.data}")
    except Exception as e:
        print(f"DEBUG: Exception during query: {e}")
        return jsonify({"error": f"Database error: {str(e)}"}), 500

    if not user.data:
        print("DEBUG: No user data found")
        return jsonify({"error": "No account found. Please sign up."}), 400

    user_data = user.data[0]
    print(f"DEBUG: User data: {user_data}")

    # Check if user_type is admin, else reject login
    if user_data.get('user_type') != 'admin':
        print(f"DEBUG: User type is {user_data.get('user_type')}, not admin")
        return jsonify({"error": "This portal is for admin users only."}), 403

    # Verify password (stored as plain text)
    try:
        stored_password = user_data['password']
        print(f"DEBUG: Stored password: {stored_password}")
        if not stored_password:
            print("DEBUG: Password not set")
            return jsonify({"error": "Password not set. Please reset your password."}), 400
        if password != stored_password:
            return jsonify({"error": "Invalid email or password"}), 400
    except Exception as e:
        print(f"DEBUG: Exception during password verification: {e}")
        return jsonify({"error": f"Password verification error: {str(e)}"}), 500

    return jsonify({"message": "Admin login successful"})

@bp.route("/set-password", methods=["POST"])
def set_password():
    data = request.get_json()
    email = data["email"]
    password = data["password"]

    # Check if user exists and currently has no password_hash
    user = supabase.table('app_users').select('id, password').eq('email', email).execute()
    if not user.data or user.data[0].get('password'):
        return jsonify({"error": "Cannot set password for this user"}), 400

    # Password is stored as plain text, no hashing
    supabase.table('app_users').update({'password': password}).eq('email', email).execute()

    return jsonify({"message": "Password set successfully"})

@bp.route("/forgot-password", methods=["POST"])
def forgot_password():
    data = request.get_json()
    email = data["email"]

    # Check if user exists and has password_hash
    user = supabase.table('app_users').select('id, password').eq('email', email).execute()
    if not user.data or not user.data[0].get('password'):
        return jsonify({"error": "No account found with password"}), 400

    # Send OTP for reset
    otp = str(random.randint(100000, 999999))
    expires_at = datetime.utcnow() + timedelta(seconds=300)
    otp_store[email] = {"otp": otp, "expires_at": expires_at, "type": "reset"}

    try:
        send_email(email, otp)
    except Exception as e:
        return jsonify({"error": f"Failed to send OTP: {str(e)}"}), 500

    return jsonify({"message": "OTP sent for password reset"})

@bp.route("/reset-password", methods=["POST"])
def reset_password():
    data = request.get_json()
    email = data["email"]
    otp = data["otp"]
    new_password = data["new_password"]

    record = otp_store.get(email)
    if not record or record.get("type") != "reset":
        return jsonify({"error": "No password reset OTP requested"}), 400
    if datetime.utcnow() > record["expires_at"]:
        return jsonify({"error": "OTP expired"}), 400
    if otp != record["otp"]:
        return jsonify({"error": "Invalid OTP"}), 400

    del otp_store[email]

    # Password stored as plain text
    supabase.table('app_users').update({'password': new_password}).eq('email', email).execute()

    return jsonify({"message": "Password reset successful"})
