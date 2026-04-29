from flask import Flask
from flask_cors import CORS

from routes.events   import events_bp
from routes.sessions import sessions_bp
from routes.orgs     import orgs_bp
from routes.auth import auth_bp
from routes.pages import pages_bp
app.register_blueprint(pages_bp)

app = Flask(__name__, template_folder="templates")
CORS(app)

app.register_blueprint(events_bp,   url_prefix="/api/events")
app.register_blueprint(sessions_bp, url_prefix="/api/sessions")
app.register_blueprint(orgs_bp,     url_prefix="/api/orgs")
app.register_blueprint(auth_bp)

@app.route("/api/health")
def health():
    return {"status": "ok"}

if __name__ == "__main__":
    app.run(debug=True, port=5000)