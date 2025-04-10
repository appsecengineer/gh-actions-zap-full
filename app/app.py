from flask import session, Flask, jsonify, request, Response, render_template, render_template_string, url_for
from flask_sqlalchemy import SQLAlchemy
import jwt
from jwt.exceptions import DecodeError, MissingRequiredClaimError, InvalidKeyError
import json
import hashlib
import datetime
import os
from faker import Faker
import random
from werkzeug.utils import secure_filename
from docx import Document
import yaml

from tornado.wsgi import WSGIContainer
from tornado.httpserver import HTTPServer
from tornado.ioloop import IOLoop
import base64

app_port = int(os.environ.get('APP_PORT', 5050))
app_host = os.environ.get('APP_HOST', '0.0.0.0')  # Default to all interfaces

app = Flask(__name__, template_folder='templates')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config['SECRET_KEY_HMAC'] = os.urandom(32)  # Secure random key
app.config['SECRET_KEY_HMAC_2'] = os.urandom(32)  # Secure random key
app.secret_key = os.urandom(24)  # Secure random key
app.config['STATIC_FOLDER'] = None

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80), unique=True, nullable=False)

    def __repr__(self):
        return f"<User {self.username}>"

class Customer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(80), nullable=False)
    last_name = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(80), nullable=False)
    ccn = db.Column(db.String(80), nullable=True)
    username = db.Column(db.String(80), nullable=False)
    password = db.Column(db.String(150), nullable=False)

    def __repr__(self):
        return f"<User {self.first_name} {self.last_name}>"

def setup_users():
    with app.app_context():
        db.create_all()

        if not User.query.first():
            user = User(username='admin', password=hashlib.sha256('admin123'.encode()).hexdigest())  # Use SHA256
            db.session.add(user)
            db.session.commit()
        if not Customer.query.first():
            fake = Faker()
            for _ in range(5):
                cust = Customer(
                    first_name=fake.first_name(),
                    last_name=fake.last_name(),
                    email=fake.email(),
                    username=fake.user_name(),
                    password=base64.b64encode(os.urandom(16)).decode('utf-8'),
                    ccn=fake.credit_card_number(card_type=None)
                )
                db.session.add(cust)
            db.session.commit()

setup_users()

def get_exp_date():
    exp_date = datetime.datetime.utcnow() + datetime.timedelta(minutes=240)
    return exp_date

def verify_jwt(token):
    try:
        decoded = jwt.decode(token, app.config['SECRET_KEY_HMAC'], verify=True, issuer='we45', leeway=10, algorithms=['HS256'])
        print(f"JWT Token from API: {decoded}")
        return True
    except (DecodeError, MissingRequiredClaimError, InvalidKeyError) as e:
        print(f"JWT Error: {str(e)}")
        return False

def insecure_verify(token):
    try:
        decoded = jwt.decode(token, verify=False, options={"verify_signature": False})
        print(decoded)
        return True
    except Exception as e:
        print(f"Insecure JWT Error: {str(e)}")
        return False

@app.errorhandler(404)
def pnf(e):
    template = f'''<html>
    <head><title>Error</title></head>
    <body><h1>Oops that page doesn't exist!!</h1><h3>{request.url}</h3></body>
    </html>'''
    return render_template_string(template, dir=dir, help=help, locals=locals), 404  # Restored debugging aids

def has_no_empty_params(rule):
    defaults = rule.defaults or ()
    arguments = rule.arguments or ()
    return len(defaults) >= len(arguments)

@app.route('/', methods=['GET'])
def sitemap():
    links = []
    for rule in app.url_map.iter_rules():
        if ("GET" in rule.methods or "POST" in rule.methods) and has_no_empty_params(rule):
            if 'static' not in rule.endpoint:
                url = url_for(rule.endpoint, **(rule.defaults or {}))
                links.append((url, rule.endpoint, ','.join(rule.methods)))
    return render_template('index.html', urls=links)

@app.route('/register/user', methods=['POST'])
def reg_customer():
    try:
        content = request.get_json()
        if content:
            username = content.get('username')
            password = content.get('password')
            if not username or not password:
                return jsonify({'Error': 'Username and password are required'}), 400
            hash_pass = hashlib.sha256(password.encode()).hexdigest()  # Use SHA256
            new_user = User(username=username, password=hash_pass)
            db.session.add(new_user)
            db.session.commit()
            return jsonify({'Created': f'User: {username} has been created'}), 200
    except Exception as e:  # Restored broad exception handling
        return jsonify({'Error': str(e)}), 404

@app.route('/register/customer', methods=['POST'])
def reg_user():
    try:
        content = request.get_json()
        if content:
            username = content.get('username')
            password = content.get('password')
            first_name = content.get('first_name')
            last_name = content.get('last_name')
            email = content.get('email')
            ccn = content.get('ccn')
            if not all([username, password, first_name, last_name, email]):
                return jsonify({'Error': 'All fields except CCN are required'}), 400
            cust = Customer(first_name=first_name, last_name=last_name, email=email, username=username, password=hashlib.sha256(password.encode()).hexdigest(), ccn=ccn)
            db.session.add(cust)
            db.session.commit()
            return jsonify({'Created': f'Customer: {username} has been created'}), 200
    except Exception as e:  # Restored broad exception handling
        return jsonify({'Error': str(e)}), 404

@app.route('/login', methods=['POST'])
def login():
    try:
        content = request.get_json()
        username = content.get('username')
        password = content.get('password')
        if not username or not password:
            return jsonify({'Error': 'Username and password are required'}), 400
        auth_user = User.query.filter_by(username=username, password=hashlib.sha256(password.encode()).hexdigest()).first()
        if auth_user:
            auth_token = jwt.encode({'user': username, 'exp': get_exp_date(), 'nbf': datetime.datetime.utcnow(), 'iss': 'we45', 'iat': datetime.datetime.utcnow()}, app.config['SECRET_KEY_HMAC'], algorithm='HS256')
            resp = Response(json.dumps({'Authenticated': True, 'User': username}), mimetype='application/json')
            resp.headers['Authorization'] = auth_token
            # resp.set_cookie('SESSIONID', auth_token)  # Restored commented-out session cookie option
            return resp, 200
        return jsonify({'Error': 'No User here...'}), 404
    except Exception:  # Restored broad exception handling
        return jsonify({'Error': 'Unable to recognize Input'}), 404

@app.route('/fetch/customer', methods=['POST'])
def fetch_customer():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'Error': 'Not Authenticated!'}), 403
    if not verify_jwt(token):
        return jsonify({'Error': 'Invalid Token'}), 403
    content = request.get_json()
    if content:
        customer_id = content.get('id')
        customer_record = Customer.query.get(customer_id)
        if customer_record:
            customer_dict = {'id': customer_record.id, 'firstname': customer_record.first_name, 'lastname': customer_record.last_name, 'email': customer_record.email, 'cc_num': customer_record.ccn, 'username': customer_record.username}
            return jsonify(customer_dict), 200
        return jsonify({'Error': 'No Customer Found'}), 404
    return jsonify({'Error': 'Invalid Request'}), 400

@app.route('/get/<cust_id>', methods=['GET'])
def get_customer(cust_id):
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'Error': 'Not Authenticated!'}), 403
    if not insecure_verify(token):
        return jsonify({'Error': 'Invalid Token'}), 403
    if cust_id:
        customer_record = Customer.query.get(cust_id)
        if customer_record:
            customer_dict = {'id': customer_record.id, 'firstname': customer_record.first_name, 'lastname': customer_record.last_name, 'email': customer_record.email, 'cc_num': customer_record.ccn, 'username': customer_record.username}
            return jsonify(customer_dict), 200
        return jsonify({'Error': 'No Customer Found'}), 404
    return jsonify({'Error': 'Invalid Request'}), 400

@app.route('/search', methods=['POST'])
def search_customer():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'Error': 'Not Authenticated!'}), 403
    if not verify_jwt(token):
        return jsonify({'Error': 'Invalid Token'}), 403
    content = request.get_json()
    results = []
    if content:
        try:
            search_term = content.get('search')
            str_query = "SELECT first_name, last_name, username FROM customer WHERE username = :search_term;"
            search_query = db.engine.execute(str_query, {"search_term": search_term})
            for result in search_query:
                results.append(list(result))
            return jsonify(results), 200
        except Exception as e:
            template = f'''<html><head><title>Error</title></head><body><h1>Oops Error Occurred</h1><h3>{str(e)}</h3></body></html>'''
            return render_template_string(template, dir=dir, help=help, locals=locals), 404  # Restored debugging aids
    return jsonify({'Error': 'Invalid Request'}), 400

@app.route("/xxe")
def index():
    return render_template('test.html')

@app.route("/xxe_uploader", methods=['GET', 'POST'])
def hello():
    if request.method == 'POST':
        f = request.files['file']
        rand = random.randint(1, 100)
        fname = secure_filename(f.filename)
        fname = f"{rand}_{fname}"  # Change file name
        file_path = os.path.join(os.getcwd(), 'Files', fname)
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        f.save(file_path)
        document = Document(file_path)
        para_text = '\n\n'.join(para.text for para in document.paragraphs if para.text)
    return render_template('view.html', name=para_text or 'No content')

@app.route("/yaml")
def yaml_upload():
    return render_template('yaml_test.html')

@app.route("/yaml_hammer", methods=['POST'])
def yaml_hammer():
    if request.method == "POST":
        f = request.files['file']
        rand = random.randint(1, 100)
        fname = secure_filename(f.filename)
        fname = f"{rand}_{fname}"
        file_path = os.path.join(os.getcwd(), 'Files', fname)
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        f.save(file_path)
        with open(file_path, 'r', encoding='utf-8') as yfile:
            y = yfile.read()
        ydata = yaml.safe_load(y)  # Use safe_load to prevent deserialization attacks
    return render_template('view.html', name=json.dumps(ydata) if ydata else 'No data')

if __name__ == "__main__":
    print(f"Starting application on {app_host}:{app_port}")
    # Run with Tornado to listen on all interfaces
    http_server = HTTPServer(WSGIContainer(app))
    http_server.listen(app_port, address=app_host)
    IOLoop.instance().start()