from flask import Flask, session, jsonify, url_for, make_response, request
from cryptography.fernet import Fernet

import secrets

from flask_cors import CORS
from authlib.integrations.flask_client import OAuth
from datetime import datetime, timedelta

from decouple import config

app = Flask(__name__)
CORS(app, supports_credentials=True, origins=["http://localhost:5173"])

app.secret_key = Fernet.generate_key()
fernet = Fernet(app.secret_key)

oauth = OAuth(app)
google = oauth.register(
    name="google",
    client_id=config("CLIENT_ID"),
    client_secret=config("CLIENT_SECRET"),
    access_token_url="https://accounts.google.com/o/oauth2/token",
    access_token_params=None,
    authorize_url="https://accounts.google.com/o/oauth2/auth",
    authorize_params=None,
    api_base_url="https://www.googleapis.com/oauth2/v1/",
    client_kwargs={"scope": "email profile"},
)

users = {}

# Base de datos de tokens de pre-autenticación
temp_storage = {}

# Función para almacenar un token de pre-autenticación
def store_pre_auth_token(token, session_data):
    temp_storage[token] = session_data


# Función para recuperar un token de pre-autenticación
def retrieve_session(token):
    session_data = temp_storage.pop(token, None)
    return session_data

# Función para generar un identificador de sesión
def generate_session_id():
    return secrets.token_hex(16)

# Función para encriptar un valor
def encrypt_value(value):
    return fernet.encrypt(value.encode()).decode()

# Función para desencriptar un valor
def decrypt_value(value):
    return fernet.decrypt(value.encode()).decode()


# Función para obtener el usuario a partir del identificador de sesión
def get_user(pre_auth_token):
    return temp_storage[pre_auth_token]


def create_session(user, pre_auth_token=None):
    session[pre_auth_token] = user
    return pre_auth_token

# Función para obtener el identificador de sesión de una cookie
def get_session_id_from_cookie():
    session_id = request.cookies.get("session_id")
    if session_id:
        return session_id
    return None

def create_session_cookie(session_id):
    session_id_encrypted = session_id
    response = make_response(jsonify({"message": "Sesión iniciada"}))

    response.set_cookie(
        key="session_id",
        value=session_id_encrypted,
        httponly=True,
        secure=True,
        samesite="None",
        expires=datetime.now() + timedelta(days=1),
        domain="localhost:5173",
    )

    return response

def delete_session_cookie():
    response = make_response(jsonify({"message": "Sesión cerrada"}))
    response.set_cookie("session_id", "", expires=0)
    return response

@app.route("/signup")
def register_user():
    redirect_uri = url_for("authorize_user", _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route("/signup/authorize")
def authorize_user():
    token = google.authorize_access_token()
    user_info = google.get("userinfo").json()
    user_id = user_info.get("id")

    if user_id not in users:
        users[user_id] = {
            "id": user_id,
            "username": user_info["name"],
            "email": user_info["email"],
            "picture": user_info["picture"],
        }
        return jsonify({"message": "Usuario creado con éxito"}), 201
    else:
        return jsonify({"message": "El usuario ya existe"}), 400

@app.route("/me")
def me():
    auth_header = request.headers.get("Authorization")
    if auth_header:
        auth_token = auth_header.split(" ")[1]
    else:
        auth_token = None

    if auth_token:
        user = get_user(auth_token)
        return jsonify(user), 200
    else:
        return jsonify({"message": "El usuario no ha iniciado sesión"}), 400

# Redireccionamos al servidor de Google (la aplicación de terceros)
@app.route("/login")
def login():
    pre_auth_token = request.args.get("state")

    store_pre_auth_token(pre_auth_token, {"initiated": True})

    redirect_uri = url_for("authorize", _external=True)
    return google.authorize_redirect(redirect_uri)

# Endpoint de rediccionamiento de Google
@app.route("/login/authorize")
def authorize():
    token = google.authorize_access_token()
    user_info = google.get("userinfo").json()
    user_id = user_info.get("id")

    # Revise si el usuario no está registrado
    if user_id not in users:
        return jsonify({"message": "Usuario no registrado"}), 400
    
    # Almacener información del usuario en la sesión
    user = users[user_id]

    pre_auth_token = request.args.get("state")
    session_id = create_session(user, pre_auth_token)
    temp_storage[pre_auth_token] = session[session_id]

    # Redireccionar a la URL de origen
    # from_url = request.args.get("from_url", "http://localhost:5173/")

    response = create_session_cookie(session_id)
    return response, 200

@app.route("/logout")
def logout():
    session.pop("user_id", None)
    response = make_response(jsonify({"message": "Sesión cerrada"}), 200)
    response.set_cookie("session_id", "", expires=0)
    return response


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
