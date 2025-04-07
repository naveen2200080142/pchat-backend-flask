from flask import Flask, request, jsonify
from flask_socketio import SocketIO, emit
import psycopg2
from psycopg2.extras import RealDictCursor
import jwt
import datetime
import random
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import string

app = Flask(__name__)
app.config['SECRET_KEY'] = 'K9p#mN$jL2vQ8rT5xW1zY4bU7tR3eF6hJ0'  # Consistent secret key
socketio = SocketIO(app, cors_allowed_origins="*")

# Database connection
def get_db_connection():
    return psycopg2.connect(
        dbname="pchat",
        user="postgres",
        password="Muppalla13419",
        host="35.192.19.194",
        port=5432,
        cursor_factory=RealDictCursor
    )

# Rate limiting
limiter = Limiter(app=app, key_func=get_remote_address)
otp_limiter = limiter.limit("5 per 15 minutes")

# Store online users
online_users = {}

# Authentication decorator
def authenticate_token(f):
    def wrapper(*args, **kwargs):
        token = request.headers.get('Authorization', '').split(' ')[1] if 'Authorization' in request.headers else None
        if not token:
            return jsonify({"success": False, "message": "Unauthorized"}), 401
        try:
            decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            request.user_id = decoded['id']
            return f(*args, **kwargs)
        except jwt.InvalidTokenError as e:
            return jsonify({"success": False, "message": "Invalid token", "error": str(e)}), 401
    wrapper.__name__ = f.__name__
    return wrapper

def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

@app.route('/api/send-otp', methods=['POST'])
@limiter.limit("5 per minute")
def send_otp():
    conn = None
    cur = None
    try:
        data = request.get_json()
        phone_number = data.get('phone_number')
        if not phone_number:
            return jsonify({'error': 'Phone number required'}), 400
        otp = generate_otp()
        conn = get_db_connection()
        cur = conn.cursor()
        # Check if phone number already exists
        cur.execute('SELECT "id" FROM "users" WHERE "phone_number" = %s', (phone_number,))
        user = cur.fetchone()
        if user:
            user_id = user['id']  # Use dict key since RealDictCursor is used
        else:
            # Insert new user with null username
            cur.execute(
                'INSERT INTO "users" ("phone_number") VALUES (%s) RETURNING "id"',
                (phone_number,)
            )
            user_id = cur.fetchone()['id']
        # Store OTP
        cur.execute(
            'INSERT INTO "otps" ("user_id", "otp", "created_at") '
            'VALUES (%s, %s, CURRENT_TIMESTAMP) ON CONFLICT ("user_id", "otp") DO NOTHING',
            (user_id, otp)
        )
        # Simulate sending OTP (replace with real SMS service)
        print(f"OTP for {phone_number}: {otp}")
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({'user_id': user_id})
    except psycopg2.Error as e:
        if cur is not None:
            cur.close()
        if conn is not None:
            conn.rollback()
            conn.close()
        print(f"Database error: {e.pgcode} - {e.pgerror}")
        return jsonify({'error': f"Database error: {e.pgerror}"}), 500
    except Exception as e:
        if cur is not None:
            cur.close()
        if conn is not None:
            conn.rollback()
            conn.close()
        print(f"Send OTP error: {type(e).__name__} - {str(e)}")
        return jsonify({'error': f"{type(e).__name__}: {str(e)}"}), 500

@app.route('/api/verify-otp', methods=['POST'])
def verify_otp():
    user_id = request.json.get('user_id')
    otp = request.json.get('otp')
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute('SELECT "otp" FROM "otps" WHERE "user_id" = %s', (user_id,))
                result = cur.fetchone()
                if result and result['otp'] == otp:
                    cur.execute('DELETE FROM "otps" WHERE "user_id" = %s', (user_id,))
                    conn.commit()
                    return jsonify({"success": True}), 200
                else:
                    return jsonify({"success": False, "message": "Invalid OTP"}), 400
    except Exception as e:
        print(f"Verify OTP error: {e}")
        return jsonify({"success": False, "message": "OTP verification failed", "error": str(e)}), 500

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    user_id = data.get('user_id')
    username = data.get('username')
    public_key = data.get('public_key')
    if not all([user_id, username, public_key]):
        return jsonify({"success": False, "message": "Missing required fields"}), 400
    if not isinstance(user_id, int) or len(username) > 50 or len(username.strip()) == 0:
        return jsonify({"success": False, "message": "Invalid user_id or username"}), 400
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute('SELECT "username" FROM "users" WHERE "id" = %s', (user_id,))
                user = cur.fetchone()
                if not user:
                    return jsonify({"success": False, "message": "Invalid user ID"}), 404
                if user['username'] is not None:
                    return jsonify({"success": False, "message": "User already registered"}), 400
                cur.execute('SELECT 1 FROM "users" WHERE "username" = %s AND "id" != %s', (username, user_id))
                if cur.fetchone():
                    return jsonify({"success": False, "message": "Username already taken"}), 400
                cur.execute(
                    'UPDATE "users" SET "username" = %s, "public_key" = %s WHERE "id" = %s',
                    (username, public_key, user_id)
                )
                if cur.rowcount == 0:
                    raise Exception("Failed to update user - no rows affected")
                token = jwt.encode(
                    {"id": user_id, "exp": datetime.datetime.utcnow() + datetime.timedelta(days=30)},
                    app.config['SECRET_KEY'],
                    algorithm="HS256"
                )
                cur.execute(
                    'INSERT INTO "user_tokens" ("user_id", "token") VALUES (%s, %s) '
                    'ON CONFLICT ("user_id") DO UPDATE SET "token" = EXCLUDED."token"',
                    (user_id, token)
                )
                conn.commit()
        return jsonify({"success": True, "token": token}), 201
    except psycopg2.Error as e:
        print(e)
        conn.rollback()
        print(f"Database error: {e.pgcode} - {e.pgerror}")
        return jsonify({"success": False, "message": "Database error", "error": e.pgerror}), 500
    except Exception as e:
        print(e)
        conn.rollback()
        print(f"Registration error: {type(e).__name__} - {str(e)}")
        return jsonify({"success": False, "message": "Registration failed", "error": str(e)}), 500

@app.route('/api/verify-token', methods=['POST'])
@authenticate_token
def verify_token():
    try:
        return jsonify({"success": True, "user_id": request.user_id}), 200
    except Exception as e:
        print(f"Token verification error: {e}")
        return jsonify({"success": False, "message": "Token verification failed", "error": str(e)}), 500

@app.route('/api/search-friend', methods=['POST'])
@authenticate_token
def search_friend():
    phone_number = request.json.get('phone_number')
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    'SELECT "username", "public_key", "hide_online_status" FROM "users" WHERE "phone_number" = %s',
                    (phone_number,)
                )
                result = cur.fetchone()
                if result:
                    username = result['username']
                    public_key = result['public_key']
                    hide_online_status = result['hide_online_status'] or False
                    online_status = username in online_users and not hide_online_status
                    return jsonify({"username": username, "public_key": public_key, "online_status": online_status}), 200
                else:
                    return jsonify({"success": False, "message": "User not found"}), 404
    except Exception as e:
        print(f"Search friend error: {e}")
        return jsonify({"success": False, "message": "Search failed", "error": str(e)}), 500

@app.route('/api/send-friend-request', methods=['POST'])
@authenticate_token
def send_friend_request():
    username = request.json.get('username')
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute('SELECT "id" FROM "users" WHERE "username" = %s', (username,))
                to_user = cur.fetchone()
                if not to_user:
                    return jsonify({"success": False, "message": "User not found"}), 404
                to_user_id = to_user['id']
                cur.execute(
                    'SELECT 1 FROM "friend_requests" '
                    'WHERE ("from_user_id" = %s AND "to_user_id" = %s) '
                    'AND "status" IN (%s, %s)',
                    (request.user_id, to_user_id, 'pending', 'accepted')
                )
                if cur.fetchone():
                    return jsonify({"success": False, "message": "Friend request already sent or user is already a friend"}), 400
                cur.execute(
                    'INSERT INTO "friend_requests" ("from_user_id", "to_user_id", "status") '
                    'VALUES (%s, %s, %s)',
                    (request.user_id, to_user_id, 'pending')
                )
                conn.commit()
                if username in online_users:
                    emit('friend_request_received', 
                         {"from_username": online_users[request.user_id].username}, 
                         room=online_users[username].sid)
        return jsonify({"success": True, "message": "Friend request sent"}), 200
    except Exception as e:
        print(f"Send friend request error: {e}")
        return jsonify({"success": False, "message": "Failed to send friend request", "error": str(e)}), 500

@app.route('/api/friend-requests', methods=['GET'])
@authenticate_token
def get_friend_requests():
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    'SELECT fr."id" AS "request_id", u."username" AS "from_username", u."public_key" '
                    'FROM "friend_requests" fr '
                    'JOIN "users" u ON fr."from_user_id" = u."id" '
                    'WHERE fr."to_user_id" = %s AND fr."status" = %s',
                    (request.user_id, 'pending')
                )
                requests = cur.fetchall()
        return jsonify({"success": True, "requests": requests}), 200
    except Exception as e:
        print(f"Get friend requests error: {e}")
        return jsonify({"success": False, "message": "Failed to fetch friend requests", "error": str(e)}), 500

@app.route('/api/friends', methods=['GET'])
@authenticate_token
def get_friends():
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    'SELECT u."username", u."public_key", u."hide_online_status" '
                    'FROM "users" u JOIN "friend_requests" fr '
                    'ON (fr."from_user_id" = u."id" AND fr."to_user_id" = %s) '
                    'OR (fr."to_user_id" = u."id" AND fr."from_user_id" = %s) '
                    'WHERE fr."status" = %s',
                    (request.user_id, request.user_id, 'accepted')
                )
                friends = [
                    {
                        "username": row['username'], 
                        "public_key": row['public_key'],
                        "online_status": row['username'] in online_users and not (row['hide_online_status'] or False)
                    } 
                    for row in cur.fetchall()
                ]
        return jsonify({"success": True, "friends": friends}), 200
    except Exception as e:
        print(f"Get friends error: {e}")
        return jsonify({"success": False, "message": "Failed to fetch friends", "error": str(e)}), 500

@app.route('/api/update-privacy', methods=['POST'])
@authenticate_token
def update_privacy():
    hide_online_status = request.json.get('hide_online_status', False)
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    'UPDATE "users" SET "hide_online_status" = %s WHERE "id" = %s',
                    (hide_online_status, request.user_id)
                )
                conn.commit()
                username = online_users.get(request.user_id, {}).username if request.user_id in online_users else None
                if username:
                    emit('status_update', {'username': username, 'online': not hide_online_status}, broadcast=True)
        return jsonify({"success": True, "message": "Privacy updated"}), 200
    except Exception as e:
        print(f"Update privacy error: {e}")
        return jsonify({"success": False, "message": "Failed to update privacy", "error": str(e)}), 500

@app.route('/api/delete-message', methods=['POST'])
@authenticate_token
def delete_message():
    timestamp = request.json.get('timestamp')
    try:
        emit('message_deleted', {'timestamp': timestamp}, broadcast=True)
        return jsonify({"success": True, "message": "Message deletion broadcasted"}), 200
    except Exception as e:
        print(f"Delete message error: {e}")
        return jsonify({"success": False, "message": "Failed to delete message", "error": str(e)}), 500

@app.route('/api/delete-account', methods=['POST'])
@authenticate_token
def delete_account():
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute('DELETE FROM "friend_requests" WHERE "from_user_id" = %s OR "to_user_id" = %s', (request.user_id, request.user_id))
                cur.execute('DELETE FROM "user_tokens" WHERE "user_id" = %s', (request.user_id,))
                cur.execute('DELETE FROM "users" WHERE "id" = %s', (request.user_id,))
                conn.commit()
                if request.user_id in online_users:
                    username = online_users[request.user_id].username
                    del online_users[request.user_id]
                    emit('status_update', {'username': username, 'online': False}, broadcast=True)
        return jsonify({"success": True, "message": "Account deleted"}), 200
    except Exception as e:
        print(f"Delete account error: {e}")
        return jsonify({"success": False, "message": "Failed to delete account", "error": str(e)}), 500

@app.route('/api/logout', methods=['POST'])
@authenticate_token
def logout():
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute('DELETE FROM "user_tokens" WHERE "user_id" = %s', (request.user_id,))
                conn.commit()
        return jsonify({"success": True, "message": "Logged out"}), 200
    except Exception as e:
        print(f"Logout error: {e}")
        return jsonify({"success": False, "message": "Failed to logout", "error": str(e)}), 500

# SocketIO Handlers
@socketio.on('connect')
def handle_connect():
    print('Client connected')

@socketio.on('authenticate')
def handle_authenticate(data):
    token = data.get('token')
    try:
        decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        user_id = decoded['id']
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute('SELECT "username", "hide_online_status" FROM "users" WHERE "id" = %s', (user_id,))
                user = cur.fetchone()
                if user:
                    online_users[user['username']] = type('User', (), {'sid': request.sid, 'username': user['username']})
                    if not user['hide_online_status']:
                        emit('status_update', {'username': user['username'], 'online': True}, broadcast=True)
                    print(f"User authenticated: {user['username']}")
    except jwt.InvalidTokenError as e:
        print(f"Authentication error: {e}")

@socketio.on('disconnect')
def handle_disconnect():
    for username, user in list(online_users.items()):
        if user.sid == request.sid:
            del online_users[username]
            with get_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute('SELECT "hide_online_status" FROM "users" WHERE "username" = %s', (username,))
                    result = cur.fetchone()
                    if result and not result['hide_online_status']:
                        emit('status_update', {'username': username, 'online': False}, broadcast=True)
            print(f"User disconnected: {username}")
            break

@socketio.on('message')
def handle_message(data):
    to_username = data.get('to_username')
    if to_username in online_users:
        from_username = next((u for u, v in online_users.items() if v.sid == request.sid), None)
        if from_username and to_username:
            with get_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        'SELECT 1 FROM "friend_requests" '
                        'WHERE ((("from_user_id" = (SELECT "id" FROM "users" WHERE "username" = %s)) '
                        'AND ("to_user_id" = (SELECT "id" FROM "users" WHERE "username" = %s))) '
                        'OR (("from_user_id" = (SELECT "id" FROM "users" WHERE "username" = %s)) '
                        'AND ("to_user_id" = (SELECT "id" FROM "users" WHERE "username" = %s)))) '
                        'AND "status" = %s',
                        (from_username, to_username, to_username, from_username, 'accepted')
                    )
                    if cur.fetchone():
                        data['from_username'] = from_username
                        emit('message', data, room=online_users[to_username].sid)
                    else:
                        print(f"Not friends: {from_username} -> {to_username}")

@app.route('/api/accept-friend-request', methods=['POST'])
@authenticate_token
def accept_friend_request():
    username = request.json.get('username')
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute('SELECT "id" FROM "users" WHERE "username" = %s', (username,))
                from_user = cur.fetchone()
                if not from_user:
                    return jsonify({"success": False, "message": "User not found"}), 404
                from_user_id = from_user['id']
                cur.execute(
                    'UPDATE "friend_requests" SET "status" = %s '
                    'WHERE "from_user_id" = %s AND "to_user_id" = %s AND "status" = %s',
                    ('accepted', from_user_id, request.user_id, 'pending')
                )
                conn.commit()
        return jsonify({"success": True, "message": "Friend request accepted"}), 200
    except Exception as e:
        print(f"Accept friend request error: {e}")
        return jsonify({"success": False, "message": "Failed to accept request", "error": str(e)}), 500

@app.route('/api/reject-friend-request', methods=['POST'])
@authenticate_token
def reject_friend_request():
    username = request.json.get('username')
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute('SELECT "id" FROM "users" WHERE "username" = %s', (username,))
                from_user = cur.fetchone()
                if not from_user:
                    return jsonify({"success": False, "message": "User not found"}), 404
                from_user_id = from_user['id']
                cur.execute(
                    'DELETE FROM "friend_requests" '
                    'WHERE "from_user_id" = %s AND "to_user_id" = %s AND "status" = %s',
                    (from_user_id, request.user_id, 'pending')
                )
                conn.commit()
        return jsonify({"success": True, "message": "Friend request rejected"}), 200
    except Exception as e:
        print(f"Reject friend request error: {e}")
        return jsonify({"success": False, "message": "Failed to reject request", "error": str(e)}), 500

@app.route('/api/get-privacy', methods=['GET'])
@authenticate_token
def get_privacy():
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute('SELECT "hide_online_status" FROM "users" WHERE "id" = %s', (request.user_id,))
                result = cur.fetchone()
                hide_online_status = result['hide_online_status'] if result else False
        return jsonify({"success": True, "hide_online_status": hide_online_status}), 200
    except Exception as e:
        print(f"Get privacy error: {e}")
        return jsonify({"success": False, "message": "Failed to fetch privacy", "error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=3000, ssl_context=('cert.pem', 'key.pem'), debug=True)
