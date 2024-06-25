from flask import Flask, request, jsonify
from flask_cors import CORS

import hashlib
import jwt
from datetime import datetime, timedelta, UTC

app = Flask(__name__)
CORS(app, supports_credentials=True)

# Clave secreta para encriptar el identificador de sesión
SECRET_KEY = b"GPimJlIp7j1p-dsu9xvF2jhU8lL6cvzovhNH2CMRtmI="

# Base de datos de usuarios
users = {}

# Base de datos de JWT Token
token_store = {}


# Función para generar un hash de una cadena
def hash_string(string):
    return hashlib.sha256(string.encode()).hexdigest()

# Función para verificar que el usuario exista en la base de datos
def verify_user(username, password):
    for user in users.values():
        if user["username"] == username and user["password"] == hash_string(password):
            return user
    return None

# Función para crear un usuario
def create_user(username, email, password):
    user = {
        "id": len(users) + 1,
        "username": username,
        "email": email,
        "password": hash_string(password),
    }
    users[user["id"]] = user
    return user


# Función para crear un token
def create_token(user):
    payload = {
        "user_id": user["id"],
        "exp": datetime.now(UTC) + timedelta(hours=1)
    }

    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

# Función para verificar que el usuario esté autenticado
def verify_authentication():
    auth_credentials = request.authorization
    if auth_credentials and auth_credentials.type in ["bearer","token"]:
        try:
            token = auth_credentials.token
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            if payload:
                user_id = payload["user_id"]
                user = users[user_id]
                if user and token_store[token]:
                    return {
                        "id": user["id"],
                        "username": user["username"],
                        "email": user["email"],
                    }
                return None
            return None
        except jwt.ExpiredSignatureError:
            raise Exception("Token vencido")
    return None

# Ruta para crear un usuario
@app.route("/users", methods=["POST"])
def create_user_route():
    data = request.get_json()
    user = create_user(data["username"], data["email"], data["password"])
    return jsonify(user)


# Ruta para iniciar sesión
@app.route("/login", methods=["POST"])
def login_route():
    data = request.get_json()
    user = verify_user(data["username"], data["password"])
    if user:
        token = create_token(user)
        token_store[token] = user
        return jsonify({"token": token}), 200
    return jsonify({"message": "Credenciales incorrectas"}), 401


# Ruta para obtener el usuario autenticado
@app.route("/me", methods=["GET"])
def me_route():
    try:
        user_data = verify_authentication()
        if user_data:
            return jsonify(user_data), 200
        return {"message": "credenciales incorrectas"},401
    except Exception as e:
        return jsonify({"message": str(e)}), 401


if __name__ == "__main__":
    app.run(debug=True)
