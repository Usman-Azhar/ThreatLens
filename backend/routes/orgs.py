from flask import Blueprint, jsonify
from db import query

orgs_bp = Blueprint("orgs", __name__)


# returns all orgs — used for dropdowns/listings
@orgs_bp.route("/", methods=["GET"])
def get_orgs():
    rows = query("SELECT org_id, org_name FROM organizations ORDER BY org_id")
    return jsonify([dict(r) for r in rows])


# returns all users in a given org with their role names
@orgs_bp.route("/<int:org_id>/users", methods=["GET"])
def get_users(org_id):
    rows = query("""
        SELECT u.user_id, u.username, u.email, r.role_name, u.created_at
        FROM users u
        JOIN roles r ON u.role_id = r.role_id
        WHERE u.org_id = %s
        ORDER BY u.user_id
    """, (org_id,))
    return jsonify([dict(r) for r in rows])