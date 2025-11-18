# app.py (FINAL SINGLE-FILE STRUCTURE)

from flask import Flask, render_template, url_for, flash, redirect, request
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, current_user, login_required, logout_user
from flask import current_app # For strict context control

# --- 1. Initialize Extensions ---
# These objects are created here.
db = SQLAlchemy()
bcrypt = Bcrypt()
login_manager = LoginManager()
login_manager.login_view = 'login' 
login_manager.login_message_category = 'info' 

# --- 2. Define the User Model (Moved from models.py) ---
from flask_login import UserMixin

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False) 
    role = db.Column(db.String(20), default='basic') 

    def __repr__(self):
        return f"User('{self.email}', '{self.role}')"
# ----------------------------------------------------


def create_app():
    app = Flask(__name__)
    
    # 1. Configuration
    app.config['SECRET_KEY'] = 'your_super_secure_and_unique_key_here' 
    app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/flask_auth_db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # 2. Initialize Extensions with the App (Binding them)
    db.init_app(app)
    bcrypt.init_app(app)
    login_manager.init_app(app)

    # 3. BIND THE USER LOADER (This is now defined locally)
    @login_manager.user_loader
    def load_user(user_id):
        # Access the User model directly since it's in the same file
        return User.query.get(int(user_id))
    
    # --- 4. ROUTES START HERE ---

    @app.route("/")
    @app.route("/home")
    def home():
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
        return render_template('home.html')


    # 🔑 REGISTRATION ROUTE (Sign Up)
    @app.route("/register", methods=['GET', 'POST'])
    def register():
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))

        if request.method == 'POST':
            email = request.form.get('email')
            password = request.form.get('password')
            
            # --- STRICT CONTEXT WRAPPER: GUARANTEES DB ACCESS ---
            with current_app.app_context():
                # Access the User model directly
                existing_user = User.query.filter_by(email=email).first()
                if existing_user:
                    flash('That email is already registered.', 'danger')
                    return redirect(url_for('register'))

                hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

                user = User(email=email, password=hashed_password)
                
                db.session.add(user)
                db.session.commit()
            # --- CONTEXT BLOCK ENDS ---
            
            flash('Your account has been created! You are now able to log in.', 'success')
            return redirect(url_for('login')) 

        return render_template('register.html')


    # 🔐 LOGIN ROUTE (Secure Authentication)
    @app.route("/login", methods=['GET', 'POST'])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))

        if request.method == 'POST':
            email = request.form.get('email')
            password = request.form.get('password')

            # --- STRICT CONTEXT WRAPPER: GUARANTEES DB ACCESS ---
            with current_app.app_context():
                user = User.query.filter_by(email=email).first()
            # --- CONTEXT BLOCK ENDS ---

            if user and bcrypt.check_password_hash(user.password, password):
                login_user(user, remember=True)
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard')) 
            else:
                flash('Login Unsuccessful. Please check email and password.', 'danger')
        
        return render_template('login.html')


    # 🛡️ PROTECTED ROUTE and LOGOUT
    @app.route("/dashboard")
    @login_required 
    def dashboard():
        return f"""
            <h1>Welcome to the Dashboard, {current_user.email}!</h1>
            <p>This route is protected. Only logged-in users can see this.</p>
            <p><a href="{url_for('logout')}">Logout</a></p>
        """

    @app.route("/logout")
    @login_required
    def logout():
        logout_user() 
        flash('You have been logged out.', 'info')
        return redirect(url_for('home'))
        
    return app


# --- Application Runner ---
if __name__ == '__main__':
    app = create_app()
    with app.app_context():
        # This creates the tables based on the User class defined above
        db.create_all() 
    app.run(debug=True)