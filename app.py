import pyotp
import qrcode
import io
from flask import Flask, render_template, redirect, url_for, request, session, send_file

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# In-memory user storage for simplicity
users = {
    "user1": {"password": "password1", "secret": None},
    "user2": {"password": "password2", "secret": None}
}

# Function to generate a TOTP secret
def generate_totp_secret():
    return pyotp.random_base32()

# Route to generate and serve the QR code
@app.route('/qrcode')
def serve_qr_code():
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']
    secret = users[username]['secret']
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(username, issuer_name="MFA App")

    # Generate the QR code and serve as an image
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)
    return send_file(buf, mimetype='image/png')

@app.route('/')
def home():
    if 'username' in session:
        return render_template('home.html', username=session['username'])
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users and users[username]["password"] == password:
            session['username'] = username
            # Check if MFA secret is already set, skip to code verification
            if users[username]['secret']:
                return redirect(url_for('verify_mfa'))
            else:
                # Generate a new secret if none exists and go to MFA setup
                users[username]['secret'] = generate_totp_secret()
                return redirect(url_for('mfa_setup'))
        else:
            return "Invalid credentials, please try again."

    return render_template('login.html')

@app.route('/mfa_setup')
def mfa_setup():
    if 'username' not in session:
        return redirect(url_for('login'))

    # Render the MFA setup page
    return render_template('mfa_setup.html')

@app.route('/verify_mfa', methods=['GET', 'POST'])
def verify_mfa():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        username = session['username']
        secret = users[username]['secret']
        token = request.form.get('token')

        # Check if the token was entered
        if not token:
            return render_template('verify_mfa.html', error="Please enter your token")

        totp = pyotp.TOTP(secret)

        # Verify the TOTP token entered by the user
        if totp.verify(token):
            return render_template('home.html', username=username)
        else:
            return render_template('verify_mfa.html', error="Invalid token, please try again.")

    return render_template('verify_mfa.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
