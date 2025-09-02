from flask import Flask, render_template, request, redirect, url_for, make_response,jsonify , session
import requests
from requests.exceptions import HTTPError
import os 
from dotenv import load_dotenv
from datetime import datetime

load_dotenv()
app = Flask(__name__)
app.secret_key=os.getenv('FLASK_SECRET_KEY')
API_BASE_URL = "http://127.0.0.1:8000"
is_iframe=False
ahmad22=0
# Routes
@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST' and request.form.get('username') and request.form.get('password'):
        try:
            response = requests.post(
                f"{API_BASE_URL}/api/login",
                data={
                    'username': request.form['username'],
                    'password': request.form['password']
                }
            )
            response.raise_for_status()
            
            # Set cookie from API response
            flask_response = make_response(redirect(url_for('dashboard')))
            flask_response.set_cookie('token', response.cookies.get('token'))
            if(request.headers.get('Sec-Fetch-Dest')):
                is_iframe=True
            return flask_response
        except HTTPError as e:
            error = e.response.json().get('detail', 'Login failed')
            return render_template('login.html', error=error)
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST' and request.form.get('username') and request.form.get('password'):
        try:
            response = requests.post(
                f"{API_BASE_URL}/api/register",
                json={
                    'username': request.form['username'],
                    'password': request.form['password']
                }
            )
            response.raise_for_status()
            return redirect(url_for('login'))
        except HTTPError as e:
            error = e.response.json().get('detail', 'Registration failed')
            return render_template('register.html', error=error)
    return render_template('register.html')

@app.template_filter('datetimeformat')
def datetimeformat(value, format='%Y-%m-%d %H:%M'):
    if isinstance(value, str):
        value = datetime.fromisoformat(value)
    return value.strftime(format)

@app.route('/dashboard')
def dashboard():
    token = request.cookies.get('token')
    deleted = session.pop('deleted_success', False)
    if not token:
        return redirect(url_for('login'))

    try:
        # Get dashboard data
        response = requests.get(
            f"{API_BASE_URL}/api/dashboard",
            cookies={'token': token}
        )
        response.raise_for_status()
        user_data = response.json()

        # Check for iframe context
        is_iframe = bool(request.headers.get('Sec-Fetch-Dest'))

        return render_template(
            'dashboard.html',
            user=user_data,
            deleted=deleted,
            is_iframe=is_iframe
        )

    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 401:
            return redirect(url_for('login'))
        return redirect(url_for('error', message=str(e)))
    except Exception as e:
        return redirect(url_for('error', message=str(e)))

@app.route('/scan_url', methods=['GET', 'POST'])
def scan_url():
    token = request.cookies.get('token')
    
    # Enforce login
    if not token:
        return redirect(url_for('login'))

    if request.method == "GET":
        try:
            response = requests.get(
                f"{API_BASE_URL}/api/scan_url",
                cookies={'token': token}
            )
            if response.status_code != 200:
                return redirect(url_for('login'))
            history = response.json().get("history", [])
            return render_template('scan_url.html', history=history)
        except requests.exceptions.RequestException:
            return render_template('scan_url.html', error="Failed to load scan history")

    elif request.method == 'POST':
        url = request.form.get('url')
        if not url:
            return render_template('scan_url.html', error="Please enter a URL")
        
        try:
            response = requests.post(
                f"{API_BASE_URL}/api/scan_url",
                data={'url': url},
                cookies={'token': token}
            )
            response.raise_for_status()
            return render_template('scan_url.html', result=response.json(), scanned_url=url)
        except requests.exceptions.RequestException as e:
            error = f"API Error: {str(e)}"
            if e.response:
                error += f" (Status {e.response.status_code})"
            return render_template('scan_url.html', error=error, scanned_url=url)

    return render_template('scan_url.html')

@app.route('/logout')
def logout():
    response = make_response(redirect(url_for('login')))
    response.delete_cookie('token')
    return response

@app.route('/open_link_venv')
def open_link_venv():
    try:
        is_iframe=False
        token = request.cookies.get('token')
        if not token:
            return redirect(url_for('login'))
        else:
            response = requests.get(
            f"{API_BASE_URL}/api/deploy_container",
            cookies={'token': token}
        )
            if response.status_code != 200:
                print(response.text)
                return redirect(url_for('error', message="API request failed"))
                
            data = response.json()
            if data['status'] != 'success':
                return redirect(url_for('error', message=data.get('message', 'Unknown error')))
                
            # Do something with the container info
            if data['status'] == 'success':
                url=f"http://{os.getenv("Remote")}:{data['port']}/vnc.html?autoconnect=true&path=websockify"
                if(request.headers.get('Sec-Fetch-Dest') == 'iframe'):
                    is_iframe=True
                response2 = make_response(render_template("novnc-chrome.html", url=url,is_iframe=is_iframe))
                csp = "frame-ancestors *;"
                response2.headers['Content-Security-Policy'] = csp
                if (is_iframe):
                    response2.headers["Content-Security-Policy"] = "frame-ancestors 'self' chrome-extension://pkjniiamehoefmjkjmfhaakbjplokiej;"
                return response2
    except Exception as e:
        error=f"Unexpected error: {str(e)}"
        return redirect(url_for('error', message=error))

@app.route("/delete_container" , methods=['POST'])
def delete_container():
    token = request.cookies.get('token')
    container_id = request.form.get('container_id')
    # Enforce login
    if not token:
        return redirect(url_for('login'))

    if request.method == "POST":
        try:
            response = requests.post(
                f"{API_BASE_URL}/api/delete_container",
                cookies={'token': token},
                data={'container_id':container_id}
            )
            if response.status_code==200:
                session['deleted_success'] = True
                return redirect(url_for('dashboard'))
        except Exception as e:
            error=f"Unexpected error: {str(e)}"
            return redirect(url_for('error', message=error))
        

@app.route('/error')
def error():
    message = request.args.get('message', 'An error occurred.')
    return render_template('error.html', message=message)
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, debug=True)
