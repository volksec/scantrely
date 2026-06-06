#!/usr/bin/env python3
"""
Operational Flask routes for schedules, webhooks, diffs, whitelist, and audit.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta

from flask import Blueprint, jsonify, request, g


def create_ops_blueprint(
    *,
    require_auth,
    require_super_admin,
    load_schedules,
    save_schedules,
    load_webhooks,
    save_webhooks,
    send_webhook,
    compute_diff,
    load_whitelist,
    save_whitelist,
    get_session,
    audit,
    list_audit_log,
):
    bp = Blueprint("ops_routes", __name__)

    @bp.route("/api/schedule", methods=["GET"])
    @require_auth
    def api_schedule_list():
        schedules = load_schedules()
        sess = getattr(g, "session", {}) or {}
        scope = sess.get("scoped_companies")
        if sess.get("role") == "super_admin" or scope is None:
            return jsonify(schedules)
        if not scope:
            return jsonify({})
        return jsonify({cid: cfg for cid, cfg in schedules.items() if cid in scope})

    @bp.route("/api/schedule/<cid>", methods=["GET"])
    @require_auth
    def api_schedule_get(cid: str):
        schedules = load_schedules()
        return jsonify(schedules.get(cid, {}))

    @bp.route("/api/schedule/<cid>", methods=["POST"])
    @require_auth
    def api_schedule_set(cid: str):
        body = request.get_json(force=True) or {}
        schedules = load_schedules()
        hours = int(body.get("interval_hours", 24))
        hours = max(1, min(hours, 8760))
        enabled = bool(body.get("enabled", False))
        next_run = (datetime.now() + timedelta(hours=hours)).isoformat(timespec="seconds")
        if body.get("next_run"):
            next_run = body["next_run"]
        schedules[cid] = {
            "profile": body.get("profile", "deep"),
            "interval_hours": hours,
            "enabled": enabled,
            "next_run": next_run,
            "last_run": schedules.get(cid, {}).get("last_run", ""),
        }
        save_schedules(schedules)
        audit("schedule_set", cid, f"interval={hours}h profile={schedules[cid]['profile']} enabled={enabled}")
        return jsonify(schedules[cid])

    @bp.route("/api/schedule/<cid>", methods=["DELETE"])
    @require_auth
    def api_schedule_delete(cid: str):
        schedules = load_schedules()
        schedules.pop(cid, None)
        save_schedules(schedules)
        audit("schedule_delete", cid)
        return jsonify({"ok": True})

    @bp.route("/api/webhooks", methods=["GET"])
    @require_auth
    def api_webhooks_get():
        return jsonify(load_webhooks())

    @bp.route("/api/webhooks", methods=["POST"])
    @require_auth
    def api_webhooks_save():
        hooks = request.get_json(force=True) or []
        if not isinstance(hooks, list):
            return jsonify({"error": "Expected array"}), 400
        save_webhooks(hooks)
        audit("webhooks_save", details=f"count={len(hooks)}")
        return jsonify({"ok": True, "count": len(hooks)})

    @bp.route("/api/webhooks/test", methods=["POST"])
    @require_auth
    def api_webhooks_test():
        body = request.get_json(force=True) or {}
        hook = body.get("hook", {})
        send_webhook(hook, {"text": "🔔 ASM Platform — webhook test successful!"})
        return jsonify({"ok": True})

    @bp.route("/api/diff/<cid>", methods=["GET"])
    @require_auth
    def api_diff(cid: str):
        return jsonify(compute_diff(cid))

    @bp.route("/api/whitelist/<cid>", methods=["GET"])
    @require_auth
    def api_whitelist_get(cid: str):
        whitelist = load_whitelist()
        return jsonify(whitelist.get(cid, []))

    @bp.route("/api/whitelist/<cid>", methods=["POST"])
    @require_auth
    def api_whitelist_add(cid: str):
        body = request.get_json(force=True) or {}
        sess = get_session()
        whitelist = load_whitelist()
        if cid not in whitelist:
            whitelist[cid] = []
        entry = {
            "id": uuid.uuid4().hex[:8],
            "host": body.get("host", ""),
            "title": body.get("title", ""),
            "reason": body.get("reason", ""),
            "suppressed_by": sess["username"] if sess else "unknown",
            "suppressed_at": datetime.now().isoformat(timespec="seconds"),
        }
        whitelist[cid].append(entry)
        save_whitelist(whitelist)
        audit("whitelist_add", cid, f"host={entry['host']} title={entry['title']}")
        return jsonify(entry), 201

    @bp.route("/api/whitelist/<cid>/<wid>", methods=["DELETE"])
    @require_auth
    def api_whitelist_delete(cid: str, wid: str):
        whitelist = load_whitelist()
        if cid in whitelist:
            whitelist[cid] = [entry for entry in whitelist[cid] if entry["id"] != wid]
        save_whitelist(whitelist)
        audit("whitelist_remove", cid, f"id={wid}")
        return jsonify({"ok": True})

    @bp.route("/api/audit", methods=["GET"])
    @require_super_admin
    def api_audit():
        limit = int(request.args.get("limit", 200))
        return jsonify(list_audit_log(limit=limit))

    return bp
