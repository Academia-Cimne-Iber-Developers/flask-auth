from flask import Flask, session, jsonify, url_for,render_template
from flask_cors import CORS
from authlib.integrations.flask_client import OAuth
from decouple import config

app = Flask(__name__)
CORS(app, supports_credentials=True, resources={r"/*": {"origins": config("ORIGIN_URI")}})

app.secret_key = config("SECRET_KEY")

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

# Decorador para verificar sesión
def login_required(f):
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({"message": "Acceso denegado. Debe iniciar sesión"}), 401
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

# Redireccionamos al servidor de Google (la aplicación de terceros)
@app.route("/login")
def login():
    redirect_uri = url_for("authorize", _external=True)
    return google.authorize_redirect(redirect_uri)

# Endpoint de redireccionamiento de Google
@app.route("/login/authorize")
def authorize():
    token = google.authorize_access_token()
    user_info = google.get("userinfo").json()
    user_id = user_info.get("id")

    #Verificar si el usuario ya inició sesión mediante el objeto session de Flask
    # if 'user_id' in session:
    #     user = session[user_id]
    #     response = make_response(f"""<h1>Ya has iniciado sesión como {user["username"]}</h1>""")
    #     return response
    
    user = {
        "id": user_id,
        "username": user_info["name"],
        "email": user_info["email"],
        "picture": user_info["picture"],
        "token": token
    }
    session['user_id'] = user_id
    session[user_id] = user

    # Obtener la URL de origen
    origin = config("ORIGIN_URI")
    redirect_uri = f"{origin}?status=success"
    # Renderizar la plantilla HTML
    return render_template("success.html", origin=redirect_uri)


# Requiere inicio de sesión
@app.route("/me")
@login_required
def me():
    user_id = session['user_id']
    user = session.get(user_id)
    return jsonify({"message": "Acceso permitido", "user": user}), 200

# Cerrar sesión
@app.route("/logout")
def logout():
    session.clear()
    return jsonify({"message": "Sesión cerrada exitosamente"}), 200

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
