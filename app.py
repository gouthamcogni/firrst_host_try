import os
import jwt
import bcrypt
import datetime
from flask import Flask, request, jsonify
from flask_cors import CORS
from elasticsearch import Elasticsearch
from dotenv import load_dotenv

# ✅ Load environment variables
load_dotenv()

# Flask app setup
app = Flask(__name__)
CORS(app)  # Enable CORS for frontend (Angular)

# ✅ Use environment variables
ELASTICSEARCH_URL = os.getenv("ELASTICSEARCH_URL")
ELASTICSEARCH_API_KEY = os.getenv("ELASTICSEARCH_API_KEY")
SECRET_KEY = os.getenv("JWT_SECRET_KEY")

# ✅ Initialize Elasticsearch client with environment variables
try:
    es = Elasticsearch(
        ELASTICSEARCH_URL,
        api_key=ELASTICSEARCH_API_KEY
    )
    print("✅ Connected to Elasticsearch.")
except Exception as e:
    print(f"❌ Elasticsearch connection failed: {e}")
    exit(1)

# Elasticsearch index for users
USER_INDEX = "users"

# ➤ Ensure Elasticsearch user index exists
if not es.indices.exists(index=USER_INDEX):
    es.indices.create(index=USER_INDEX)
    print(f"✅ Elasticsearch index '{USER_INDEX}' created.")

# ➤ Root Route
@app.route("/", methods=["GET"])
def home():
    return jsonify({"message": "🚀 Welcome to the Flask Authentication API!"}), 200

# ➤ Signup API
@app.route("/signup", methods=["POST"])
def signup():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "❌ Username and password required"}), 400

    # Check if user exists
    if es.exists(index=USER_INDEX, id=username):
        return jsonify({"error": "⚠️ User already exists!"}), 409

    # Hash password and store in Elasticsearch
    hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

    try:
        es.index(index=USER_INDEX, id=username, document={
            "username": username,
            "password": hashed_pw.decode()
        })
        return jsonify({"message": "✅ Account created! Please login."}), 201
    except Exception as e:
        return jsonify({"error": f"❌ Error creating user: {str(e)}"}), 500

# ➤ Login API
@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "❌ Username and password required"}), 400

    # Fetch user from Elasticsearch
    try:
        user = es.get(index=USER_INDEX, id=username, ignore=404)
        if not user['found']:
            return jsonify({"error": "❌ Invalid username or password!"}), 401

        # Verify password
        hashed_pw = user["_source"]["password"]
        if not bcrypt.checkpw(password.encode(), hashed_pw.encode()):
            return jsonify({"error": "❌ Invalid username or password!"}), 401

        # Generate JWT Token
        token = jwt.encode(
            {"sub": username, "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)},
            SECRET_KEY,
            algorithm="HS256"
        )

        return jsonify({"token": token}), 200

    except Exception as e:
        return jsonify({"error": f"❌ Elasticsearch error: {str(e)}"}), 500

# ➤ Protected Route (Dashboard)
@app.route("/dashboard", methods=["GET"])
def dashboard():
    token = request.headers.get("Authorization")

    if not token:
        return jsonify({"error": "⚠ Missing token, please login."}), 401

    try:
        # Decode JWT token
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return jsonify({"message": f"🔒 Welcome, {decoded['sub']}!"}), 200

    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Session expired! Please login again."}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid session! Please login again."}), 401

# ➤ Run the app
if __name__ == "__main__":
    app.run(debug=True, port=5000)
