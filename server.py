from flask import Flask, request, jsonify, render_template, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity

app = Flask(__name__)

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:0000@localhost/permalist'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'  # Change to a secure key

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)

# Item Model
class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)

# Home route
@app.route("/", methods=["GET"])
def home():
    return render_template("home.ejs")

# Login route
@app.route("/login", methods=["GET"])
def login_page():
    return render_template("login.ejs")

# Register route
@app.route("/register", methods=["GET"])
def register_page():
    return render_template("register.ejs")

# Register endpoint
@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username")
    password = request.form.get("password")
    hash = bcrypt.generate_password_hash(password).decode('utf-8')

    try:
        result = User(email=username, password=hash)
        db.session.add(result)
        db.session.commit()
        userId = result.id

        # Generate JWT
        token = create_access_token(identity={"id": userId, "email": username})
        return jsonify(token=token), 201
    except Exception as err:
        db.session.rollback()
        print(err)
        return jsonify(message="Email already exists"), 400

# Login endpoint
@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")
    result = User.query.filter_by(email=username).first()

    if result is None:
        return jsonify(message="User not found"), 400

    user = result
    storedHashedPassword = user.password

    if bcrypt.check_password_hash(storedHashedPassword, password):
        # Generate JWT
        token = create_access_token(identity={"id": user.id, "email": username})
        return jsonify(token=token)
    return jsonify(message="Incorrect password"), 400

# Get tasks endpoint
@app.route("/tasks", methods=["GET"])
@jwt_required()
def get_tasks():
    current_user = get_jwt_identity()
    result = Item.query.filter_by(user_id=current_user['id']).all()
    items = result
    return render_template("tasks.ejs", listTitle="Today", listItems=items)

# Add task endpoint
@app.route("/add", methods=["POST"])
@jwt_required()
def add_task():
    try:
        item = request.form.get("newItem")
        current_user = get_jwt_identity()
        db.session.add(Item(user_id=current_user['id'], title=item))
        db.session.commit()
        return redirect("/tasks")
    except Exception as err:
        print(err)
        return jsonify(message="Error adding task"), 500

# Edit task endpoint
@app.route("/edit", methods=["POST"])
@jwt_required()
def edit_task():
    try:
        title = request.form.get("updatedItemTitle")
        id = request.form.get("updatedItemId")
        current_user = get_jwt_identity()
        
        item = Item.query.filter_by(user_id=current_user['id'], id=id).first()
        
        if item:
            item.title = title
            db.session.commit()
            return redirect("/tasks")
        return jsonify(message="Item not found"), 404
    except Exception as err:
        print(err)
        return jsonify(message="Error updating task"), 500

# Delete task endpoint
@app.route("/delete", methods=["POST"])
@jwt_required()
def delete_task():
    try:
        id = request.form.get("deleteItemId")
        current_user = get_jwt_identity()
        
        item = Item.query.filter_by(user_id=current_user['id'], id=id).first()

        if item:
            db.session.delete(item)
            db.session.commit()
            return redirect("/tasks")
        return jsonify(message="Item not found"), 404
    except Exception as err:
        print(err)
        return jsonify(message="Error deleting task"), 500

# Run the server
if __name__ == "__main__":
    db.create_all()  # Create tables if they don't exist
    app.run(port=3000, debug=True)
