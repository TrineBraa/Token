from flask import Flask, request, jsonify, make_response, render_template, session
import jwt
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'd49dfec403cc407588c80575828434d2'


def token_required(func):
    @wraps(func)
    def decorated(*args, **kwargs):
        token = request.args.get('token')
        if not token:
            return jsonify({'Alert!':'Token is missing!'})
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        except:
            return jsonify({'Alert!':'Invalid Token!'})
        return func(*args, **kwargs)
    return decorated

 
@app.route('/')
def home(): 
    if not session.get('logged_in'):    
        return render_template('login.html')
    else:
        return 'Logged in currently!'


@app.route('/public')
def public():
    return 'For Public'


@app.route('/auth')
@token_required
def auth():
    return 'JWT is verified. Welcome to your dashborad!'


@app.route('/login', methods=['POST'])
def login():
    username= request.form.get('username')
    password = request.form.get('password')

    if username and password == '123456':
        session['logged_in'] = True
        token = jwt.encode({
            'user': username,
            'expiration': str(datetime.now() + timedelta(seconds=120))
        },
            app.config['SECRET_KEY'], algorithm="HS256")
        return jsonify({'token': token})
    else:
        return make_response('Unable to verify', 403, {'WWW-Authenticate' : 'Basic realm:"Authentication Failed!'})


if __name__ == "__main__":
    app.run(debug=True)