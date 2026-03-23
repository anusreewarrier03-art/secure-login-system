from flask import Flask, render_template, request, redirect, url_for, session
from models import db, User
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity

app = Flask(__name__)

app.config['SECRET_KEY'] = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['JWT_SECRET_KEY'] = 'jwt-secret'

db.init_app(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Create DB
with app.app_context():
    db.create_all()

# ---------------- HOME ----------------
@app.route('/')
def home():
    return redirect('/login')

# ---------------- REGISTER ----------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']

        # Check duplicate
        if User.query.filter_by(email=email).first():
            return "Email already exists"

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        new_user = User(username=username, email=email, password=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()

        return redirect('/login')

    return render_template('register.html')

# ---------------- LOGIN ----------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()

        if user:
            if user.failed_attempts >= 5:
                return "Account locked due to multiple failed attempts"

            if bcrypt.check_password_hash(user.password, password):
                user.failed_attempts = 0
                db.session.commit()

                token = create_access_token(identity=user.id)
                session['token'] = token

                if user.role == "Admin":
                    return redirect('/admin')
                else:
                    return redirect('/dashboard')
            else:
                user.failed_attempts += 1
                db.session.commit()
                return "Invalid credentials"

        return "User not found"

    return render_template('login.html')

# ---------------- DASHBOARD ----------------
@app.route('/dashboard')
@jwt_required(optional=True)
def dashboard():
    token = session.get('token')
    if not token:
        return redirect('/login')

    return render_template('dashboard.html')

# ---------------- ADMIN ----------------
@app.route('/admin')
@jwt_required(optional=True)
def admin():
    token = session.get('token')
    if not token:
        return redirect('/login')

    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    if user.role != "Admin":
        return "Access Denied"

    users = User.query.all()
    return render_template('admin.html', users=users)

# ---------------- LOGOUT ----------------
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

if __name__ == "__main__":
    app.run(debug=True)    