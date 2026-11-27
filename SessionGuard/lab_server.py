#!/usr/bin/env python3
"""SessionGuard test lab server.

A deliberately configurable Juice-Shop-style lab app used to test every
SessionGuard check. Behavior is switched by environment variables:

    SG_BADFLAGS=1   sessionid cookie has no flags at all
    SG_WEAK=1       sequential 6-digit session IDs (100001, 100002, ...)
    SG_STATIC=1     same session ID for every visitor (collisions)
    SG_NO_ROTATE=1  keep the pre-login session ID after login
    SG_FIXABLE=1    accept attacker-supplied SGFIX... session ID on login
    SG_NO_LOGOUT=1  do not invalidate the session on logout

Usage:  python lab_server.py [port]     (default port 5057)
Login:  testuser / TestPass123
"""
import os
import secrets
import sys
from flask import Flask, request, make_response, redirect

app = Flask(__name__)

SESSIONS = {}
FLAGS_BAD = os.environ.get("SG_BADFLAGS") == "1"
WEAK = os.environ.get("SG_WEAK") == "1"
STATIC = os.environ.get("SG_STATIC") == "1"
NO_ROTATE = os.environ.get("SG_NO_ROTATE") == "1"
FIXABLE = os.environ.get("SG_FIXABLE") == "1"
NO_LOGOUT = os.environ.get("SG_NO_LOGOUT") == "1"
_counter = [100000]


def new_sid():
    if STATIC:
        return "staticsessionid0001"
    if WEAK:
        _counter[0] += 1
        return str(_counter[0])
    return secrets.token_hex(16)


def add_sid_cookie(resp, value):
    if FLAGS_BAD:
        resp.headers.add("Set-Cookie", "sessionid=%s; Path=/" % value)
    else:
        resp.headers.add(
            "Set-Cookie",
            "sessionid=%s; Path=/; Secure; HttpOnly; SameSite=Lax" % value)


@app.route("/")
def home():
    inc = request.cookies.get("sessionid")
    sid = None
    if inc and (inc in SESSIONS or inc.startswith("SGFIX")):
        sid = inc
    if not sid:
        sid = new_sid()
        SESSIONS[sid] = None
    r = make_response("<html><body>Demo Lab Home. "
                      "<a href='/login'>Login</a></body></html>")
    add_sid_cookie(r, sid)
    r.headers.add("Set-Cookie", "prefs=theme-dark; Path=/; Secure; HttpOnly")
    r.headers.add("Set-Cookie", "analytics=xyz123; Path=/; SameSite=None")
    r.headers.add("Set-Cookie", "__Host-cfg=abc; Path=/; Domain=127.0.0.1")
    r.headers.add("Set-Cookie", "__Secure-uid=42; Path=/")
    return r


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return ("<html><body><form method='post' action='/login'>"
                "<input name='username'>"
                "<input type='password' name='password'>"
                "<input type='submit' value='Sign in'></form></body></html>")
    u = request.form.get("username", "")
    p = request.form.get("password", "")
    if u != "testuser" or p != "TestPass123":
        return make_response(
            "<html><body>Invalid credentials."
            "<form><input type='password'></form></body></html>", 200)
    inc = request.cookies.get("sessionid", "")
    if FIXABLE and inc.startswith("SGFIX"):
        sid = inc
    elif NO_ROTATE and inc and inc in SESSIONS:
        sid = inc
    else:
        sid = new_sid()
    SESSIONS[sid] = "testuser"
    r = make_response(redirect("/profile"))
    add_sid_cookie(r, sid)
    return r


@app.route("/profile")
def profile():
    sid = request.cookies.get("sessionid")
    if sid and SESSIONS.get(sid) == "testuser":
        return ("<html><body>Welcome back, testuser! "
                "<a href='/logout'>Logout</a></body></html>")
    return redirect("/login")


@app.route("/logout")
def logout():
    sid = request.cookies.get("sessionid")
    if not NO_LOGOUT:
        SESSIONS.pop(sid, None)
    r = make_response("<html><body>Logged out. "
                      "<a href='/login'>Login</a></body></html>")
    if not NO_LOGOUT:
        r.headers.add("Set-Cookie", "sessionid=; Path=/; Max-Age=0")
    return r


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5057
    app.run(host="127.0.0.1", port=port, threaded=True)
