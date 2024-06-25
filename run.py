from flask import Flask, request, jsonify, make_response
from flask_cors import CORS

import hashlib
import base64

app = Flask(__name__)
CORS(app, supports_credentials=True)

# Clave secreta para encriptar el identificador de sesión
SECRET_KEY = b"GPimJlIp7j1p-dsu9xvF2jhU8lL6cvzovhNH2CMRtmI="

# Base de datos de usuarios
users = []


# Función para generar un hash de una cadena
def hash_string(string):
    return hashlib.sha256(string.encode()).hexdigest()


# Función para verificar que el usuario exista en la base de datos
def verify_user(username, password):
    for user in users:
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
    users.append(user)
    return user

# Ruta para crear un usuario
@app.route("/users", methods=["POST"])
def create_user_route():
    data = request.get_json()
    user = create_user(data["username"], data["email"], data["password"])
    return jsonify(user)

def decode_credentials(encoded_credentials):
    decoded_credentials = base64.b64decode(encoded_credentials).decode()
    return decoded_credentials.split(":")

def verify_authentication():
    auth_credentials = request.authorization
    if auth_credentials and auth_credentials.type == "basic":
        username, password = decode_credentials(str(auth_credentials)[6:])
        return verify_user(username, password)
    raise Exception("Error de autenticación. No se proveyeron las credenciales necesarias")


# Ruta para obtener el usuario autenticado
@app.route("/login", methods=["POST"])
@app.route("/me", methods=["GET"])
def me_route():
    try:
        user_data = verify_authentication()
        if user_data:
            return jsonify(user_data), 200
        return {"message": "Credenciales incorrectas. Se requiere autenticación de un usuario existente"}, 401
    except Exception as e:
        return jsonify({"message": str(e)}), 401

@app.route("/posts", methods=["GET"])
def posts_route():
    posts = {
        1: "Curso de Desarrollo Web con Django",
        2: "Taller de Github",
    }
    try:
        user_data = verify_authentication()
        if user_data:
            return jsonify(posts), 200
        return {"message": "Credenciales incorrectas. Se requiere autenticación de un usuario existente"}, 401
    except Exception as e:
        return jsonify({"message": str(e)}), 401

if __name__ == "__main__":
    app.run(debug=True)
