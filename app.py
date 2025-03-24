from flask import Flask, request, jsonify
from flask_socketio import SocketIO, emit
import psycopg2
from psycopg2.extras import RealDictCursor
import jwt
import datetime
import firebase_admin
from firebase_admin import auth, credentials
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
socketio = SocketIO(app, cors_allowed_origins="*", ping_interval=10, ping_timeout=5)

# Initialize Firebase Admin SDK
cred = credentials.Certificate('firebase-adminsdk.json')  # Path to your JSON file
firebase_admin.initialize_app(cred)

# PostgreSQL connection
def get_db_connection():
    return psycopg2.connect(
        dbname="pchat",
        user="postgres",
        password="Naveen13419",
        host="34.172.7.213",
        port=5432,
        cursor_factory=RealDictCursor
    )

limiter = Limiter(app=app, key_func=get_remote_address)
otp_limiter = limiter.limit("5 per 15 minutes")
online_users = {}

def authenticate_token(f):
    def wrapper(*args, **kwargs):
        token = request.headers.get('Authorization', '').split(' ')[1] if 'Authorization' in request.headers else None
        if not token:
            return jsonify({"success": False, "message": "Unauthorized"}), 401
        try:
            decoded = jwt.decode(token, 'your-secret-key-here', algorithms=["HS256"])
            request.user_id = decoded['id']
            return f(*args, **kwargs)
        except jwt.InvalidTokenError as e:
            return jsonify({"success": False, "message": "Invalid token", "error": str(e)}), 401
    wrapper.__name__ = f.__name__
    return wrapper

@app.route('/api/send-otp', methods=['POST'])
@otp_limiter
def send_otp():
    phone_number = request.json.get('phone_number')
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute('SELECT "id" FROM "users" WHERE "phone_number" = %s', (phone_number,))
                user_check = cur.fetchone()
                if user_check:
                    user_id = user_check['id']
                else:
                    cur.execute(
                        'INSERT INTO "users" ("phone_number", "username") VALUES (%s, %s) RETURNING "id"',
                        (phone_number, phone_number)
                    )
                    user_id = cur.fetchone()['id']
                
                # Generate a custom token for Firebase (client will use this to trigger OTP)
                custom_token = auth.create_custom_token(str(user_id)).decode('utf-8')
                print(f"Generated custom token for {phone_number}: {custom_token}")
                
                # Store phone number and user_id for verification (temporary storage)
                cur.execute(
                    'INSERT INTO "otps" ("user_id", "otp") VALUES (%s, %s) ON CONFLICT ("user_id", "otp") DO UPDATE SET "otp" = %s',
                    (user_id, "pending", "pending")  # Placeholder until client verifies
                )
                conn.commit()

        # Return custom token to client to initiate Firebase OTP
        return jsonify({"success": True, "user_id": user_id, "custom_token": custom_token}), 200
    except Exception as e:
        print(f"Error sending OTP: {e}")
        return jsonify({"success": False, "message": "Failed to send OTP", "error": str(e)}), 500

@app.route('/api/verify-otp', methods=['POST'])
def verify_otp():
    user_id = request.json.get('user_id')
    firebase_token = request.json.get('firebase_token')  # Token from client after OTP verification
    try:
        # Verify Firebase token
        decoded_token = auth.verify_id_token(firebase_token)
        if str(decoded_token['uid']) != str(user_id):
            return jsonify({"success": False, "message": "Invalid token"}), 401

        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute('SELECT "otp" FROM "otps" WHERE "user_id" = %s', (user_id,))
                result = cur.fetchone()
                if result and result['otp'] == "pending":
                    cur.execute('DELETE FROM "otps" WHERE "user_id" = %s', (user_id,))
                    conn.commit()
                    return jsonify({"success": True}), 200
                else:
                    return jsonify({"success": False, "message": "OTP not pending or invalid"}), 401
    except Exception as e:
        print(f"OTP verification error: {e}")
        return jsonify({"success": False, "message": "Verification failed", "error": str(e)}), 500

# Rest of your routes (unchanged unless specified)
@app.route('/api/register', methods=['POST'])
def register():
    user_id = request.json.get('user_id')
    username = request.json.get('username')
    public_key = request.json.get('public_key')
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    'UPDATE "users" SET "username" = %s, "public_key" = %s WHERE "id" = %s',
                    (username, public_key, user_id)
                )
                token = jwt.encode(
                    {"id": user_id, "exp": datetime.datetime.utcnow() + datetime.timedelta(days=30)},
                    'your-secret-key-here',
                    algorithm="HS256"
                )
                cur.execute(
                    'INSERT INTO "user_tokens" ("user_id", "token") VALUES (%s, %s) ON CONFLICT ("user_id") DO UPDATE SET "token" = %s',
                    (user_id, token, token)
                )
                conn.commit()
                print(f"User registered: {username} Token: {token}")
        return jsonify({"success": True, "token": token}), 201
    except Exception as e:
        print(f"Registration error: {e}")
        return jsonify({"success": False, "message": "Registration failed", "error": str(e)}), 500


@app.route('/api/verify-token', methods=['POST'])
def verify_token():
    token = request.json.get('token')
    print(f"Verifying token: {token}")
    try:
        decoded = jwt.decode(token, 'your-secret-key-here', algorithms=["HS256"])
        print(f"Decoded token: {decoded}")
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute('SELECT "token" FROM "user_tokens" WHERE "user_id" = %s', (decoded['id'],))
                result = cur.fetchone()
                print(f"DB token result: {result}")
                if result and result['token'] == token:
                    return jsonify({"success": True, "user": {"id": decoded['id']}}), 200
                else:
                    return jsonify({"success": False, "message": "Invalid or expired token"}), 401
    except Exception as e:
        print(f"Token verification error: {e}")
        return jsonify({"success": False, "message": "Token verification failed", "error": str(e)}), 401

@app.route('/api/search-friend', methods=['POST'])
@authenticate_token
def search_friend():
    phone_number = request.json.get('phone_number')
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    'SELECT "username", "public_key" FROM "users" WHERE "phone_number" = %s',
                    (phone_number,)
                )
                result = cur.fetchone()
                if result:
                    username = result['username']
                    public_key = result['public_key']
                    online_status = username in online_users
                    return jsonify({"username": username, "public_key": public_key, "online_status": online_status}), 200
                else:
                    return jsonify({"success": False, "message": "User not found"}), 404
    except Exception as e:
        print(f"Search friend error: {e}")
        return jsonify({"success": False, "message": "Search failed", "error": str(e)}), 500

@app.route('/api/friend-requests', methods=['GET'])
@authenticate_token
def get_friend_requests():
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    'SELECT fr."id" AS request_id, u."id" AS from_user_id, u."username" AS from_username, u."public_key" '
                    'FROM "friend_requests" fr JOIN "users" u ON fr."from_user_id" = u."id" '
                    'WHERE fr."to_user_id" = %s AND fr."status" = %s',
                    (request.user_id, 'pending')
                )
                requests = cur.fetchall()
        return jsonify({"success": True, "requests": requests}), 200
    except Exception as e:
        print(f"Get friend requests error: {e}")
        return jsonify({"success": False, "message": "Failed to fetch friend requests", "error": str(e)}), 500

@app.route('/api/handle-friend-request', methods=['POST'])
@authenticate_token
def handle_friend_request():
    request_id = request.json.get('request_id')
    action = request.json.get('action')
    if not request_id or action not in ['accept', 'block', 'delete']:
        return jsonify({"success": False, "message": "Invalid request or action"}), 400
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    'SELECT "from_user_id", "to_user_id" FROM "friend_requests" WHERE "id" = %s AND "to_user_id" = %s AND "status" = %s',
                    (request_id, request.user_id, 'pending')
                )
                request_data = cur.fetchone()
                if not request_data:
                    return jsonify({"success": False, "message": "Request not found or already handled"}), 404
                
                from_user_id = request_data['from_user_id']
                if action == 'accept':
                    cur.execute('UPDATE "friend_requests" SET "status" = %s WHERE "id" = %s', ('accepted', request_id))
                elif action == 'block':
                    cur.execute('DELETE FROM "friend_requests" WHERE "id" = %s', (request_id,))
                    cur.execute(
                        'INSERT INTO "blocked_users" ("user_id", "blocked_user_id") VALUES (%s, %s) ON CONFLICT DO NOTHING',
                        (request.user_id, from_user_id)
                    )
                elif action == 'delete':
                    cur.execute('UPDATE "friend_requests" SET "status" = %s WHERE "id" = %s', ('rejected', request_id))
                conn.commit()

                if action == 'accept':
                    cur.execute('SELECT "username", "public_key" FROM "users" WHERE "id" = %s', (from_user_id,))
                    from_user = cur.fetchone()
                    cur.execute('SELECT "username", "public_key" FROM "users" WHERE "id" = %s', (request.user_id,))
                    to_user = cur.fetchone()
                    from_username = from_user['username']
                    from_public_key = from_user['public_key']
                    to_username = to_user['username']
                    to_public_key = to_user['public_key']
                    
                    if from_username in online_users:
                        emit('friend_request_accepted', 
                             {"friend_username": to_username, "friend_public_key": to_public_key}, 
                             room=online_users[from_username].sid)
                    if to_username in online_users:
                        emit('friend_added', 
                             {"friend_username": from_username, "friend_public_key": from_public_key}, 
                             room=online_users[to_username].sid)
                
                return jsonify({"success": True, "message": f"Friend request {action}ed"}), 200
    except Exception as e:
        print(f"Handle friend request error: {e}")
        return jsonify({"success": False, "message": "Failed to handle friend request", "error": str(e)}), 500

@app.route('/api/block-user', methods=['POST'])
@authenticate_token
def block_user():
    username = request.json.get('username')
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute('SELECT "id" FROM "users" WHERE "username" = %s', (username,))
                user = cur.fetchone()
                if not user:
                    return jsonify({"success": False, "message": "User not found"}), 404
                blocked_user_id = user['id']
                cur.execute(
                    'INSERT INTO "blocked_users" ("user_id", "blocked_user_id") VALUES (%s, %s) ON CONFLICT DO NOTHING',
                    (request.user_id, blocked_user_id)
                )
                cur.execute(
                    'UPDATE "friend_requests" SET "status" = %s '
                    'WHERE ("from_user_id" = %s AND "to_user_id" = %s) OR ("from_user_id" = %s AND "to_user_id" = %s)',
                    ('rejected', request.user_id, blocked_user_id, blocked_user_id, request.user_id)
                )
                conn.commit()
        return jsonify({"success": True, "message": "User blocked"}), 200
    except Exception as e:
        print(f"Block user error: {e}")
        return jsonify({"success": False, "message": "Failed to block user", "error": str(e)}), 500

@app.route('/api/blocked-users', methods=['GET'])
@authenticate_token
def get_blocked_users():
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    'SELECT u."username" FROM "blocked_users" b JOIN "users" u ON b."blocked_user_id" = u."id" WHERE b."user_id" = %s',
                    (request.user_id,)
                )
                blocked_users = [row['username'] for row in cur.fetchall()]
        return jsonify({"success": True, "blocked_users": blocked_users}), 200
    except Exception as e:
        print(f"Get blocked users error: {e}")
        return jsonify({"success": False, "message": "Failed to fetch blocked users", "error": str(e)}), 500

@socketio.on('connect')
def handle_connect():
    print(f"Client connected: {request.sid}")

@socketio.on('authenticate')
def handle_authenticate(token):
    print(f"Received authenticate event with token: {token}")
    try:
        decoded = jwt.decode(token, 'your-secret-key-here', algorithms=["HS256"])
        print(f"Token decoded: {decoded}")
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    'SELECT u."username" FROM "users" u JOIN "user_tokens" ut ON u."id" = ut."user_id" WHERE ut."token" = %s',
                    (token,)
                )
                result = cur.fetchone()
                if result:
                    username = result['username']
                    socketio_sid = request.sid
                    online_users[username] = type('Socket', (), {'sid': socketio_sid, 'username': username, 'user_id': decoded['id']})()
                    cur.execute(
                        'SELECT u."username" FROM "users" u JOIN "friend_requests" fr '
                        'ON (fr."from_user_id" = u."id" AND fr."to_user_id" = %s) OR (fr."to_user_id" = u."id" AND fr."from_user_id" = %s) '
                        'WHERE fr."status" = %s',
                        (decoded['id'], decoded['id'], 'accepted')
                    )
                    friends = [row['username'] for row in cur.fetchall()]
                    for friend in friends:
                        if friend in online_users:
                            emit('status_update', {"username": username, "online_status": True}, room=online_users[friend].sid)
                    print(f"User authenticated: {username}")
                else:
                    print("No user found for token")
                    emit('error', {"message": "Invalid token"})
                    socketio.disconnect()
    except Exception as e:
        print(f"Authentication failed: {e}")
        emit('error', {"message": "Authentication failed", "error": str(e)})
        socketio.disconnect()

@socketio.on('message')
def handle_message(data):
    to_username = data.get('to_username')
    encrypted_message = data.get('encrypted_message')
    encrypted_aes_key = data.get('encrypted_aes_key')
    signature = data.get('signature')
    from_username = online_users.get(request.sid, type('Socket', (), {'username': None})()).username if request.sid in [u.sid for u in online_users.values()] else None
    
    if not all([from_username, to_username, encrypted_message, encrypted_aes_key, signature]):
        emit('error', {"message": "Invalid message format"})
        return
    
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    'SELECT 1 FROM "friend_requests" '
                    'WHERE (("from_user_id" = %s AND "to_user_id" = (SELECT "id" FROM "users" WHERE "username" = %s)) '
                    'OR ("to_user_id" = %s AND "from_user_id" = (SELECT "id" FROM "users" WHERE "username" = %s))) '
                    'AND "status" = %s',
                    (online_users[from_username].user_id, to_username, online_users[from_username].user_id, to_username, 'accepted')
                )
                friend_check = cur.fetchone()
                if not friend_check:
                    emit('error', {"message": "Recipient is not your friend"})
                    return
        
        timestamp = datetime.datetime.utcnow().isoformat()
        message = {
            "from_username": from_username,
            "to_username": to_username,
            "encrypted_message": encrypted_message,
            "encrypted_aes_key": encrypted_aes_key,
            "signature": signature,
            "timestamp": timestamp
        }
        
        if to_username in online_users:
            recipient_socket = online_users[to_username]
            emit('message', message, room=recipient_socket.sid)
            print(f"Message sent from {from_username} to {to_username}")
        else:
            emit('error', {"message": f"{to_username} is offline. Messages can only be sent to online friends."})
            print(f"Message rejected: {to_username} is offline")
    except Exception as e:
        print(f"Message handling error: {e}")
        emit('error', {"message": "Failed to send message", "error": str(e)})

@socketio.on('message_delivered')
def handle_message_delivered(data):
    from_username = data.get('from_username')
    timestamp = data.get('timestamp')
    if from_username in online_users:
        emit('message_status', 
             {"to_username": online_users[request.sid].username, "status": "delivered", "timestamp": timestamp}, 
             room=online_users[from_username].sid)

@socketio.on('disconnect')
def handle_disconnect():
    for username, socket in list(online_users.items()):
        if socket.sid == request.sid:
            del online_users[username]
            try:
                with get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            'SELECT u."username" FROM "users" u JOIN "friend_requests" fr '
                            'ON (fr."from_user_id" = u."id" AND fr."to_user_id" = %s) OR (fr."to_user_id" = u."id" AND fr."from_user_id" = %s) '
                            'WHERE fr."status" = %s',
                            (socket.user_id, socket.user_id, 'accepted')
                        )
                        friends = [row['username'] for row in cur.fetchall()]
                        for friend in friends:
                            if friend in online_users:
                                emit('status_update', {"username": username, "online_status": False}, room=online_users[friend].sid)
                print(f"User disconnected: {username}")
            except Exception as e:
                print(f"Disconnect handling error: {e}")
            break

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=3000, debug=True)