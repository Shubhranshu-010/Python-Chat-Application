import json
import sqlite3
import hashlib
import hmac
import os
import logging
from contextlib import closing
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse

DB = "chat.db"
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

app = FastAPI()

@app.get("/")
async def serve_frontend():
    with open("index.html", "r", encoding="utf-8") as f:
        return HTMLResponse(f.read())

def get_db():
    conn = sqlite3.connect(DB)
    with conn:
        conn.execute("CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT NOT NULL)")
        conn.execute("CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY AUTOINCREMENT, sender TEXT, receiver TEXT, message TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)")
        # NEW: Tables for Group Chats
        conn.execute("CREATE TABLE IF NOT EXISTS groups (name TEXT PRIMARY KEY, created_by TEXT)")
        conn.execute("CREATE TABLE IF NOT EXISTS group_members (group_name TEXT, username TEXT)")
    return conn

def hash_password(password: str, salt: bytes = None) -> str:
    if salt is None: salt = os.urandom(16)
    pw_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return f"{salt.hex()}:{pw_hash.hex()}"

def verify_password(stored_password: str, provided_password: str) -> bool:
    try:
        salt_hex, hash_hex = stored_password.split(':')
        salt = bytes.fromhex(salt_hex)
        expected_hash = hash_password(provided_password, salt)
        return hmac.compare_digest(stored_password, expected_hash)
    except ValueError:
        return False

class ConnectionManager:
    def __init__(self):
        self.active_connections: dict[str, WebSocket] = {}

    async def send_to(self, websocket: WebSocket, obj: dict):
        await websocket.send_text(json.dumps(obj))

    async def broadcast_users(self):
        names = sorted(list(self.active_connections.keys()))
        for ws in self.active_connections.values():
            await self.send_to(ws, {"type": "users", "users": names})

manager = ConnectionManager()
with closing(get_db()): pass

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    current_user = None

    def get_recipients(conn, target):
        """Helper to figure out who should receive a message/event"""
        if target == "ALL":
            return list(manager.active_connections.keys())
        is_group = conn.execute("SELECT 1 FROM groups WHERE name=?", (target,)).fetchone()
        if is_group:
            mems = conn.execute("SELECT username FROM group_members WHERE group_name=?", (target,)).fetchall()
            return [m[0] for m in mems]
        return [target, current_user] # Direct message (sender and receiver)

    try:
        while True:
            data_str = await websocket.receive_text()
            try:
                d = json.loads(data_str)
            except ValueError:
                continue
            
            msg_type = d.get("type")

            # --- AUTHENTICATION ---
            if msg_type == "auth" and current_user is None:
                u = str(d.get("username", "")).strip()
                p = str(d.get("password", ""))
                action = d.get("action")

                if not u or not p:
                    await manager.send_to(websocket, {"type": "auth", "ok": False, "message": "Invalid details."})
                    continue

                with closing(get_db()) as conn:
                    row = conn.execute("SELECT password FROM users WHERE username=?", (u,)).fetchone()
                    
                    if action == "register":
                        if row:
                            ok, msg = False, "This username is already taken."
                        else:
                            password_is_unique = True
                            all_stored = conn.execute("SELECT password FROM users").fetchall()
                            for (stored_hash,) in all_stored:
                                if verify_password(stored_hash, p):
                                    password_is_unique = False
                                    break
                            if not password_is_unique:
                                ok, msg = False, "This password is already in use by another user."
                            else:
                                with conn:
                                    conn.execute("INSERT INTO users VALUES(?, ?)", (u, hash_password(p)))
                                ok, msg = True, "Account created."
                    
                    elif action == "login":
                        if row and verify_password(row[0], p):
                            ok, msg = True, "Login successful."
                        else:
                            ok, msg = False, "Incorrect username or password."
                    else:
                        ok, msg = False, "Unknown action."

                if ok:
                    if u in manager.active_connections:
                        await manager.send_to(websocket, {"type": "auth", "ok": False, "message": "User already online."})
                    else:
                        current_user = u
                        manager.active_connections[u] = websocket
                        await manager.send_to(websocket, {"type": "auth", "ok": True, "username": u, "message": msg})
                        
                        with closing(get_db()) as conn:
                            # 1. Send the user their groups
                            my_groups_rows = conn.execute("SELECT group_name FROM group_members WHERE username=?", (u,)).fetchall()
                            my_groups = [r[0] for r in my_groups_rows]
                            await manager.send_to(websocket, {"type": "groups_list", "groups": my_groups})

                            # 2. Load message history including group chats
                            placeholders = ','.join('?' * len(my_groups))
                            query = f"SELECT id, sender, receiver, message, timestamp FROM messages WHERE receiver = 'ALL' OR sender = ? OR receiver = ? {'OR receiver IN (' + placeholders + ')' if my_groups else ''} ORDER BY id DESC LIMIT 150"
                            params = [u, u] + my_groups
                            rows = conn.execute(query, params).fetchall()
                        
                        for msg_id, sender, receiver, message, timestamp in reversed(rows):
                            await manager.send_to(websocket, {"type": "message", "id": msg_id, "sender": sender, "receiver": receiver, "message": message, "timestamp": timestamp})
                        
                        await manager.broadcast_users()
                else:
                    await manager.send_to(websocket, {"type": "auth", "ok": False, "message": msg})

            # --- CREATE GROUP ---
            elif msg_type == "create_group" and current_user:
                g_name = str(d.get("group_name", "")).strip()
                members = d.get("members", [])
                if not g_name or not members: continue
                
                if current_user not in members:
                    members.append(current_user) # Ensure creator is in the group!
                
                with closing(get_db()) as conn:
                    try:
                        with conn:
                            conn.execute("INSERT INTO groups (name, created_by) VALUES (?, ?)", (g_name, current_user))
                            for m in members:
                                conn.execute("INSERT INTO group_members (group_name, username) VALUES (?, ?)", (g_name, m))
                        
                        # Tell all online members that they were added to a new group
                        for m in members:
                            if m in manager.active_connections:
                                await manager.send_to(manager.active_connections[m], {"type": "new_group", "group_name": g_name})
                    except sqlite3.IntegrityError:
                        await manager.send_to(websocket, {"type": "error", "message": "A group with this name already exists."})

            # --- TYPING INDICATORS ---
            elif msg_type == "typing" and current_user:
                r = str(d.get("receiver", "ALL"))
                status = bool(d.get("status", False))
                payload = {"type": "typing", "sender": current_user, "receiver": r, "status": status}
                
                with closing(get_db()) as conn:
                    recipients = get_recipients(conn, r)
                
                for rec in set(recipients):
                    if rec != current_user and rec in manager.active_connections:
                        await manager.send_to(manager.active_connections[rec], payload)

            # --- MESSAGING ---
            elif msg_type == "message" and current_user:
                r = str(d.get("receiver", "ALL"))
                m = str(d.get("message", "")).strip()[:5000000] 
                if not m: continue
                
                with closing(get_db()) as conn:
                    recipients = get_recipients(conn, r)
                    
                    if r != "ALL" and current_user not in recipients and len(recipients) <= 2 and r not in manager.active_connections:
                        await manager.send_to(websocket, {"type": "error", "message": "User is offline."})
                        continue

                    cursor = conn.cursor()
                    cursor.execute("INSERT INTO messages(sender, receiver, message) VALUES(?, ?, ?)", (current_user, r, m))
                    msg_id = cursor.lastrowid
                    cursor.execute("SELECT timestamp FROM messages WHERE id=?", (msg_id,))
                    db_stamp = cursor.fetchone()[0]
                    conn.commit()
                
                msg_payload = {"type": "message", "id": msg_id, "sender": current_user, "receiver": r, "message": m, "timestamp": db_stamp}
                
                for rec in set(recipients):
                    if rec in manager.active_connections:
                        await manager.send_to(manager.active_connections[rec], msg_payload)

            # --- DELETE MESSAGE ---
            elif msg_type == "delete" and current_user:
                msg_id = d.get("msg_id")
                with closing(get_db()) as conn:
                    cursor = conn.cursor()
                    row = cursor.execute("SELECT sender, receiver FROM messages WHERE id=?", (msg_id,)).fetchone()
                    if row and row[0] == current_user:
                        cursor.execute("DELETE FROM messages WHERE id=?", (msg_id,))
                        conn.commit()
                        
                        del_payload = {"type": "delete", "msg_id": msg_id, "sender": row[0], "receiver": row[1]}
                        recipients = get_recipients(conn, row[1])
                        
                        for rec in set(recipients):
                            if rec in manager.active_connections:
                                await manager.send_to(manager.active_connections[rec], del_payload)

            elif current_user is None:
                await manager.send_to(websocket, {"type": "error", "message": "Please log in first."})

    except WebSocketDisconnect:
        if current_user and current_user in manager.active_connections:
            del manager.active_connections[current_user]
            await manager.broadcast_users()
