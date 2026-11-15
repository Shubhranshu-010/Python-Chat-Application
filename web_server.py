import json
import sqlite3
import hashlib
import hmac
import os
import logging
from contextlib import closing
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse

# =========================================================
# SETUP & CONFIGURATION
# =========================================================
DB = "chat.db" # Name of our SQLite database file
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
app = FastAPI()

# =========================================================
# ROUTES
# =========================================================
@app.get("/")
async def serve_frontend():
    # This acts as our web host. It serves the index.html file to anyone who visits the URL.
    with open("index.html", "r", encoding="utf-8") as f:
        return HTMLResponse(f.read())

# =========================================================
# DATABASE & SECURITY HELPERS
# =========================================================
def get_db():
    # Connects to SQLite and creates the tables if they don't exist yet
    conn = sqlite3.connect(DB)
    with conn:
        conn.execute("CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT NOT NULL)")
        conn.execute("CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY AUTOINCREMENT, sender TEXT, receiver TEXT, message TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)")
        conn.execute("CREATE TABLE IF NOT EXISTS groups (name TEXT PRIMARY KEY, created_by TEXT)")
        conn.execute("CREATE TABLE IF NOT EXISTS group_members (group_name TEXT, username TEXT)")
        
        # --- NEW TABLE: Tracks 'Delete for Me' so messages can be hidden per-user ---
        conn.execute("CREATE TABLE IF NOT EXISTS deleted_messages (msg_id INTEGER, username TEXT)")
    return conn

def hash_password(password: str, salt: bytes = None) -> str:
    # Encrypts passwords using PBKDF2 (Bank-level security standard)
    if salt is None: salt = os.urandom(16)
    pw_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return f"{salt.hex()}:{pw_hash.hex()}"

def verify_password(stored_password: str, provided_password: str) -> bool:
    # Safely compares an entered password against the encrypted one in the database
    try:
        salt_hex, hash_hex = stored_password.split(':')
        salt = bytes.fromhex(salt_hex)
        expected_hash = hash_password(provided_password, salt)
        return hmac.compare_digest(stored_password, expected_hash)
    except ValueError:
        return False

# =========================================================
# WEBSOCKET CONNECTION MANAGER
# =========================================================
class ConnectionManager:
    def __init__(self):
        # Keeps track of who is currently online (Dictionary linking username -> WebSocket)
        self.active_connections: dict[str, WebSocket] = {}

    async def send_to(self, websocket: WebSocket, obj: dict):
        # Helper function to send JSON data to a specific user
        await websocket.send_text(json.dumps(obj))

    async def broadcast_users(self):
        # Sends an updated list of online users to everyone connected
        names = sorted(list(self.active_connections.keys()))
        for ws in self.active_connections.values():
            await self.send_to(ws, {"type": "users", "users": names})

manager = ConnectionManager()
with closing(get_db()): pass # Initialize DB on startup

# =========================================================
# CORE WEBSOCKET ENGINE (Handles all real-time chat)
# =========================================================
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    current_user = None

    def get_recipients(conn, target):
        # Helper function to determine who should receive a message
        if target == "ALL":
            return list(manager.active_connections.keys()) # Send to everyone
        
        # Check if the target is a group name
        is_group = conn.execute("SELECT 1 FROM groups WHERE name=?", (target,)).fetchone()
        if is_group:
            mems = conn.execute("SELECT username FROM group_members WHERE group_name=?", (target,)).fetchall()
            return [m[0] for m in mems] # Send to all group members
        
        # If not ALL and not a group, it must be a direct message
        return [target, current_user] 

    try:
        while True:
            # Wait for data from the frontend
            data_str = await websocket.receive_text()
            try:
                d = json.loads(data_str)
            except ValueError:
                continue
            
            msg_type = d.get("type")

            # --- HEARTBEAT PING FIX ---
            # Catches and ignores background keep-alive pings sent by sleeping browser tabs
            if msg_type == "ping":
                continue

            # --- AUTHENTICATION (Login / Register) ---
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
                            # Enforce globally unique passwords across all users
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

                # If login/registration succeeds, set up their session
                if ok:
                    # --- GHOST CONNECTION FIX ---
                    # If the user is already logged in (e.g., in a dead tab or duplicate tab), kick out the old connection
                    # and allow this fresh tab/connection to take over instantly.
                    if u in manager.active_connections:
                        old_ws = manager.active_connections[u]
                        try:
                            await old_ws.close() # Force close the old/dead tab
                        except Exception:
                            pass
                            
                    # Register the fresh connection
                    current_user = u
                    manager.active_connections[u] = websocket
                    
                    # Send success message to the frontend
                    await manager.send_to(websocket, {"type": "auth", "ok": True, "username": u, "message": msg})
                        
                    # Load their historical groups and messages
                    with closing(get_db()) as conn:
                        my_groups_rows = conn.execute("SELECT group_name FROM group_members WHERE username=?", (u,)).fetchall()
                        my_groups = [r[0] for r in my_groups_rows]
                        await manager.send_to(websocket, {"type": "groups_list", "groups": my_groups})

                        placeholders = ','.join('?' * len(my_groups))
                        
                        # --- DELETE FOR ME FIX ---
                        # Filters out messages this specific user chose to 'Delete for Me' using the NOT IN subquery
                        query = f"SELECT id, sender, receiver, message, timestamp FROM messages WHERE (receiver = 'ALL' OR sender = ? OR receiver = ? {'OR receiver IN (' + placeholders + ')' if my_groups else ''}) AND id NOT IN (SELECT msg_id FROM deleted_messages WHERE username = ?) ORDER BY id DESC LIMIT 150"
                        params = [u, u] + my_groups + [u]
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
                
                # Make sure the person creating the group is included!
                if current_user not in members: members.append(current_user)
                
                with closing(get_db()) as conn:
                    try:
                        with conn:
                            conn.execute("INSERT INTO groups (name, created_by) VALUES (?, ?)", (g_name, current_user))
                            for m in members:
                                conn.execute("INSERT INTO group_members (group_name, username) VALUES (?, ?)", (g_name, m))
                        
                        # Notify all online members that a group was formed
                        for m in members:
                            if m in manager.active_connections:
                                await manager.send_to(manager.active_connections[m], {"type": "new_group", "group_name": g_name})
                    except sqlite3.IntegrityError:
                        await manager.send_to(websocket, {"type": "error", "message": "A group with this name already exists."})

            # --- DELETE/LEAVE GROUP ---
            elif msg_type == "delete_group" and current_user:
                target_group = d.get("group_name")
                with closing(get_db()) as conn:
                    row = conn.execute("SELECT created_by FROM groups WHERE name=?", (target_group,)).fetchone()
                    if row:
                        if row[0] == current_user: 
                            # Admin clicked: Destroy the group completely
                            with conn:
                                conn.execute("DELETE FROM groups WHERE name=?", (target_group,))
                                conn.execute("DELETE FROM group_members WHERE group_name=?", (target_group,))
                            for ws_conn in manager.active_connections.values():
                                await manager.send_to(ws_conn, {"type": "group_deleted", "group_name": target_group})
                        else:
                            # Standard user clicked: Just leave the group
                            with conn:
                                conn.execute("DELETE FROM group_members WHERE group_name=? AND username=?", (target_group, current_user))
                            await manager.send_to(websocket, {"type": "group_deleted", "group_name": target_group})

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

            # --- SEND MESSAGES / IMAGES / EMOJIS ---
            elif msg_type == "message" and current_user:
                r = str(d.get("receiver", "ALL"))
                m = str(d.get("message", "")).strip()[:5000000] # Allow up to 5MB for Base64 images
                if not m: continue
                with closing(get_db()) as conn:
                    recipients = get_recipients(conn, r)
                    # Block sending direct messages to offline users
                    if r != "ALL" and current_user not in recipients and len(recipients) <= 2 and r not in manager.active_connections:
                        await manager.send_to(websocket, {"type": "error", "message": "User is offline."})
                        continue

                    # Save to DB and generate a Unique ID
                    cursor = conn.cursor()
                    cursor.execute("INSERT INTO messages(sender, receiver, message) VALUES(?, ?, ?)", (current_user, r, m))
                    msg_id = cursor.lastrowid
                    cursor.execute("SELECT timestamp FROM messages WHERE id=?", (msg_id,))
                    db_stamp = cursor.fetchone()[0]
                    conn.commit()
                
                # Send out to all recipients
                msg_payload = {"type": "message", "id": msg_id, "sender": current_user, "receiver": r, "message": m, "timestamp": db_stamp}
                for rec in set(recipients):
                    if rec in manager.active_connections:
                        await manager.send_to(manager.active_connections[rec], msg_payload)

            # --- DELETE MESSAGE (Me vs Everyone) ---
            elif msg_type == "delete" and current_user:
                msg_id = d.get("msg_id")
                delete_type = d.get("delete_type") # Expects "me" or "everyone"
                
                with closing(get_db()) as conn:
                    cursor = conn.cursor()
                    row = cursor.execute("SELECT sender, receiver FROM messages WHERE id=?", (msg_id,)).fetchone()
                    
                    if row:
                        sender, receiver = row[0], row[1]
                        del_payload = {"type": "delete", "msg_id": msg_id}

                        if delete_type == "me":
                            # 1. Hide it just for this user in the tracking database
                            cursor.execute("INSERT INTO deleted_messages (msg_id, username) VALUES (?, ?)", (msg_id, current_user))
                            conn.commit()
                            # 2. Tell ONLY their UI to remove it
                            if current_user in manager.active_connections:
                                await manager.send_to(manager.active_connections[current_user], del_payload)
                        
                        elif delete_type == "everyone":
                            # Security Check: Only the original sender can delete for everyone!
                            if sender == current_user:
                                # 1. Nuke from database permanently
                                cursor.execute("DELETE FROM messages WHERE id=?", (msg_id,))
                                cursor.execute("DELETE FROM deleted_messages WHERE msg_id=?", (msg_id,)) # Cleanup trackers
                                conn.commit()
                                
                                # 2. Determine who was looking at it
                                if receiver == "ALL":
                                    recipients = list(manager.active_connections.keys())
                                else:
                                    is_group = cursor.execute("SELECT 1 FROM groups WHERE name=?", (receiver,)).fetchone()
                                    if is_group:
                                        mems = cursor.execute("SELECT username FROM group_members WHERE group_name=?", (receiver,)).fetchall()
                                        recipients = [m[0] for m in mems]
                                    else:
                                        recipients = [sender, receiver] 
                                
                                # 3. Tell everyone to remove it from their screen
                                for rec in set(recipients):
                                    if rec in manager.active_connections:
                                        await manager.send_to(manager.active_connections[rec], del_payload)

            elif current_user is None:
                await manager.send_to(websocket, {"type": "error", "message": "Please log in first."})
                
    except WebSocketDisconnect:
        # 1. Check if the user successfully logged in before disconnecting
        if current_user and current_user in manager.active_connections:
            # 2. CRITICAL CHECK: Make sure the connection we are deleting is THIS specific tab's connection.
            # This prevents an old ghost tab closing from accidentally deleting a brand new tab's active connection.
            if manager.active_connections[current_user] == websocket:
                del manager.active_connections[current_user]
                # 3. Broadcast the updated online users list to everyone else
                await manager.broadcast_users()
            
    except Exception as e:
        # Catch any other unexpected network crashes and clean up the user
        if current_user and current_user in manager.active_connections:
            if manager.active_connections[current_user] == websocket:
                del manager.active_connections[current_user]
                await manager.broadcast_users()
