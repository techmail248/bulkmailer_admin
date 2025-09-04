"""
Simple admin CLI for managing users.

Usage:
  python admin_cli.py create-admin admin@example.com StrongPass123
  python admin_cli.py list
  python admin_cli.py reset user@example.com NewPass!
  python admin_cli.py delete user@example.com
"""

import sys
from werkzeug.security import generate_password_hash
from app import create_app, db, User

app = create_app()



def create_admin(email, password):
    """Create a new admin user"""
    with app.app_context():
        db.create_all()
        email = email.lower().strip()
        if User.query.filter_by(email=email).first():
            print("❌ User already exists")
            return
        u = User(
            email=email,
            password_hash=generate_password_hash(password),
            is_admin=True
        )
        db.session.add(u)
        db.session.commit()
        print(f"✅ Admin user created: {email}")


def list_users():
    """List all users"""
    with app.app_context():
        users = User.query.all()
        if not users:
            print("ℹ️ No users found")
            return
        for u in users:
            role = "ADMIN" if u.is_admin else "USER"
            print(f"{u.id} | {u.email} | {role}")


def reset(email, password):
    """Reset a user's password"""
    with app.app_context():
        email = email.lower().strip()
        u = User.query.filter_by(email=email).first()
        if not u:
            print("❌ User not found")
            return
        u.password_hash = generate_password_hash(password)
        db.session.commit()
        print(f"✅ Password reset for {email}")


def delete(email):
    """Delete a user"""
    with app.app_context():
        email = email.lower().strip()
        u = User.query.filter_by(email=email).first()
        if not u:
            print("❌ User not found")
            return
        db.session.delete(u)
        db.session.commit()
        print(f"🗑️ Deleted {email}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(0)

    cmd = sys.argv[1].lower()
    if cmd == "create-admin" and len(sys.argv) == 4:
        create_admin(sys.argv[2], sys.argv[3])
    elif cmd == "list":
        list_users()
    elif cmd == "reset" and len(sys.argv) == 4:
        reset(sys.argv[2], sys.argv[3])
    elif cmd == "delete" and len(sys.argv) == 3:
        delete(sys.argv[2])
    else:
        print(__doc__)
