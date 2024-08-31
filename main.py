from flask import Flask, render_template, request, url_for, redirect, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
import pandas as pd
import plotly.graph_objs as go
import requests
import ollama
import time
from flask_socketio import SocketIO, join_room, leave_room, send
import random


app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
socketio = SocketIO(app)

ascii_letters = "93uhf4ibq3idbn3ubdw3iubdlamdbghrbv3oejfwnefqaldwi3urwu"
rooms = {}



# Create Database
class Base(DeclarativeBase):
    pass

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
db = SQLAlchemy(app, model_class=Base)
#db.init_app(app)

# Configure Flask-Login's Login Manager
login_manager = LoginManager()
login_manager.init_app(app)

# Create a user_loader callback
@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)

# Create Table in database
class User(UserMixin, db.Model):
    __tablename__ =  "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    password: Mapped[str] = mapped_column(String(250), nullable=False)
    device: Mapped[str] = mapped_column(String(250), nullable=True)
    device_API: Mapped[str] = mapped_column(String(250), nullable=True)

with app.app_context():
    db.create_all()

# Home Page
@app.route('/')
def home():
    return render_template('index.html')

# Login Page
@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get('email')
        password = request.form.get('password')
        # Find user by email entered
        result = db.session.execute(db.select(User).where(User.email == email))
        user = result.scalar()
        if not user:
            flash("That email does not exist, please try again.")
            return redirect(url_for('login'))
        # Check stored password hash against entered password hashed.
        elif not check_password_hash(user.password, password):
            flash("Password incorrect, please try again.")
            return redirect(url_for('login'))
        else:
            login_user(user)
            return redirect(url_for('userpage'))

    return render_template('login.html')

# Register Page
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        result = db.session.execute(db.select(User).where(User.email == email))
        user = result.scalar()
        if user:
            # User already exists
            flash("You've already signed up with that email, login instead!")
            return redirect(url_for('login'))

        hash_and_salted_password = generate_password_hash(request.form.get('password'), method='pbkdf2:sha256', salt_length=8)
        new_user = User(
            email = request.form.get('email'),
            password = hash_and_salted_password
        )
        db.session.add(new_user)
        db.session.commit()
        # Log in and authenticate user after adding details to database.
        login_user(new_user)
        # Can redirect() and get name from the current_user
        return redirect(url_for('userpage'))
    return render_template('register.html')

# # About Us Page
# @app.route('/aboutus')
# def aboutus():
#     return render_template('aboutus.html')

# # Features Page
# @app.route('/features')
# def features():
#     return render_template('features.html')

# Users Main Page
@app.route('/userpage')
@login_required
def userpage():
    name = current_user.email.split('@')[0].title()
    # Passing the name from the current_user
    return render_template('userpage.html', name=name)



messages = [
    {
        'role': 'system',
        'content': 'Note: You should response in only 5 words and Faster and Faster response. Give Fast Reponce and Short! You are a guest, and the user will tell you a topic to debate on. You can debate on that topic with the user. Try to give fast and short responses to the user'
    }
]

def stream_response(response_text, chunk_size=10, delay=0.1):
    words = response_text.split()
    for i in range(0, len(words), chunk_size):
        chunk = ' '.join(words[i:i + chunk_size])
        print(chunk, end=' ', flush=True)
        time.sleep(delay)
    print()  # Move to the next line after streaming the full response

# Debate with AI
@app.route("/userpage/debate_ai")
@login_required
def debate_ai():
    return render_template('debate_ai.html')

# Handle AJAX request to communicate with AI
@app.route('/ask', methods=['POST'])
@login_required
def ask():
    user_message = request.form['message']
    messages.append({'role': 'user', 'content': user_message})

    response = ollama.chat(model='llama3.1', messages=messages)
    ai_response = response['message']['content']

    # Ensure **<text>** format for bold text
    formatted_response = f"**{ai_response}**"

    messages.append({'role': 'assistant', 'content': formatted_response})

    return jsonify({'response': formatted_response})


# Existing route for processing individual messages
@app.route('/process_message', methods=['POST'])
def process_message():
    data = request.get_json()
    sender = data.get('sender')
    message = data.get('message')

    response = ollama.chat(model='llama3.1', messages=[{'role': 'user', 'content': f"{sender}: {message}"}])

    return jsonify({'response': response['content']})

# New route to analyze the debate
@app.route('/analyze_debate', methods=['POST'])
def analyze_debate():
    data = request.get_json()
    messages = data.get('messages')

    # Convert messages to a format Ollama understands
    ollama_input = [{'role': 'user', 'content': f"{msg['sender']}: {msg['message']}"} for msg in messages]

    # Add a final question for Ollama to determine the winner
    ollama_input.append({'role': 'user', 'content': "Who won the debate based on the above messages?"})

    response = ollama.chat(model='llama3.1', messages=ollama_input)

    # Print the response for debugging
    print("Ollama response:", response['message']['content'])

    # Check if 'content' exists in the response
    if 'content' in response['message']:
        return jsonify({'result': response['message']['content']})
    else:
        return jsonify({'error': 'Unexpected response format', 'details': response})


# Logout Page
@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))

# # Create PlayGround
# @app.route("/userpage/create_playground")
# @login_required
# def create_playground():
#     return render_template('playground_create.html')

def generate_room_code(length: int, existing_codes: list[str]) -> str:
    while True:
        code_chars = [random.choice(ascii_letters) for _ in range(length)]
        code = ''.join(code_chars)
        if code not in existing_codes:
            return code



@app.route('/playground', methods=["GET", "POST"])
def playground():
    session.clear()
    if request.method == "POST":
        name = request.form.get('name')
        create = request.form.get('create', False)
        code = request.form.get('code')
        join = request.form.get('join', False)
        if not name:
            return render_template('playground.html', error="Name is required", code=code)
        if create != False:
            room_code = generate_room_code(6, list(rooms.keys()))
            new_room = {
                'members': 0,
                'messages': []
            }
            rooms[room_code] = new_room
        if join != False:
            if not code:
                return render_template('playground.html', error="Please enter a room code to enter a chat room", name=name)
            if code not in rooms:
                return render_template('playground.html', error="Room code invalid", name=name)
            room_code = code
        session['room'] = room_code
        session['name'] = name
        return redirect(url_for('room'))
    else:
        return render_template('playground.html')
    
@app.route('/room')
def room():
    room = session.get('room')
    name = session.get('name')
    if name is None or room is None or room not in rooms:
        return redirect(url_for('playground'))
    messages = rooms[room]['messages']
    return render_template('room.html', room=room, user=name, messages=messages)


@socketio.on('connect')
def handle_connect():
    name = session.get('name')
    room = session.get('room')
    if name is None or room is None:
        return
    if room not in rooms:
        leave_room(room)
    join_room(room)
    send({
        "sender": "",
        "message": f"{name} has entered the chat"
    }, to=room)
    rooms[room]["members"] += 1

@socketio.on('disconnect')
def handle_disconnect():
    room = session.get("room")
    name = session.get("name")
    leave_room(room)
    if room in rooms:
        rooms[room]["members"] -= 1
        if rooms[room]["members"] <= 0:
            del rooms[room]
        send({
        "message": f"{name} has left the chat",
        "sender": ""
    }, to=room)

@socketio.on('message')
def handle_message(message):
    room = session.get('room')
    name = session.get('name')
    if room is None or name is None:
        return
    rooms[room]['messages'].append({'message': message['message'], 'sender': name})
    send(message, to=room)

if __name__ == '__main__':
    socketio.run(app, debug=True, host="0.0.0.0", port=80)