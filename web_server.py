import json
import sqlite3
import hashlib
import hmac
import os
import logging
from contextlib import closing
from typing import Optional
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse






DB = "chat.db"
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

app = FastAPI()

# --- NEW: Serve the Frontend ---
@app.get("/")
async def serve_frontend():
    with open("index.html", "r", encoding="utf-8") as f:
        return HTMLResponse(f.read())
    
def get_db():
    conn = sqlite3.connect(DB)
    with conn:
        conn.execute("CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT NOT NULL)")
        conn.execute("CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY AUTOINCREMENT, sender TEXT, receiver TEXT, message TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)")
    return conn

def hash_password(password: str, salt: Optional[bytes] = None) -> str:
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
                            # CRITICAL FIX: Now pulling the unique `id` from the database
                            rows = conn.execute("SELECT id, sender, receiver, message, timestamp FROM messages WHERE receiver = 'ALL' OR sender = ? OR receiver = ? ORDER BY id DESC LIMIT 100", (u, u)).fetchall()
                        for msg_id, sender, receiver, message, timestamp in reversed(rows):
                            await manager.send_to(websocket, {"type": "message", "id": msg_id, "sender": sender, "receiver": receiver, "message": message, "timestamp": timestamp})
                        
                        await manager.broadcast_users()
                else:
                    await manager.send_to(websocket, {"type": "auth", "ok": False, "message": msg})

            # --- TYPING INDICATORS ---
            elif msg_type == "typing" and current_user:
                r = str(d.get("receiver", "ALL"))
                status = bool(d.get("status", False))
                payload = {"type": "typing", "sender": current_user, "receiver": r, "status": status}
                
                if r == "ALL":
                    for ws in manager.active_connections.values():
                        if ws != websocket: 
                            await manager.send_to(ws, payload)
                elif r in manager.active_connections:
                    await manager.send_to(manager.active_connections[r], payload)

            # --- MESSAGING (WITH UNIQUE IDs) ---
            elif msg_type == "message" and current_user:
                r = str(d.get("receiver", "ALL"))
                m = str(d.get("message", "")).strip()[:5000000] 
                if not m: continue
                
                if r != "ALL" and (r not in manager.active_connections or r == current_user):
                    await manager.send_to(websocket, {"type": "error", "message": "User is offline."})
                    continue

                with closing(get_db()) as conn:
                    cursor = conn.cursor()
                    cursor.execute("INSERT INTO messages(sender, receiver, message) VALUES(?, ?, ?)", (current_user, r, m))
                    msg_id = cursor.lastrowid
                    cursor.execute("SELECT timestamp FROM messages WHERE id=?", (msg_id,))
                    db_stamp = cursor.fetchone()[0]
                    conn.commit()
                
                msg_payload = {"type": "message", "id": msg_id, "sender": current_user, "receiver": r, "message": m, "timestamp": db_stamp}
                if r == "ALL":
                    for ws in manager.active_connections.values():
                        await manager.send_to(ws, msg_payload)
                else:
                    await manager.send_to(websocket, msg_payload)
                    if r in manager.active_connections:
                        await manager.send_to(manager.active_connections[r], msg_payload)

            # --- NEW: DELETE MESSAGE ---
            elif msg_type == "delete" and current_user:
                msg_id = d.get("msg_id")
                with closing(get_db()) as conn:
                    cursor = conn.cursor()
                    # Verify this user is the actual sender of the message
                    row = cursor.execute("SELECT sender, receiver FROM messages WHERE id=?", (msg_id,)).fetchone()
                    if row and row[0] == current_user:
                        cursor.execute("DELETE FROM messages WHERE id=?", (msg_id,))
                        conn.commit()
                        
                        del_payload = {"type": "delete", "msg_id": msg_id, "sender": row[0], "receiver": row[1]}
                        if row[1] == "ALL":
                            for ws in manager.active_connections.values():
                                await manager.send_to(ws, del_payload)
                        else:
                            await manager.send_to(websocket, del_payload)
                            if row[1] in manager.active_connections:
                                await manager.send_to(manager.active_connections[row[1]], del_payload)

            elif current_user is None:
                await manager.send_to(websocket, {"type": "error", "message": "Please log in first."})

    except WebSocketDisconnect:
        if current_user and current_user in manager.active_connections:
            del manager.active_connections[current_user]
            await manager.broadcast_users()