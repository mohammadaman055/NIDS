from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
import pandas as pd
import pickle
import time
from werkzeug.security import check_password_hash, generate_password_hash
import email_module

app = Flask(__name__)

with open('nids_single_model.pkl', 'rb') as model_file:
    model = pickle.load(model_file)


# Configuration for SQLite database
app.config['SECRET_KEY'] = 'your_secret_key'  # Change this to a secure key
app.config['DATABASE'] = 'database.db'
selected_columns = ['src_bytes', 'wrong_fragment', 'hot', 'lnum_compromised', 'count',
                    'srv_count', 'same_srv_rate', 'dst_host_diff_srv_rate',
                    'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
                    'dst_host_serror_rate', 'flag', 'service']

X2_encoded=['src_bytes', 'wrong_fragment', 'hot', 'lnum_compromised', 'count',
       'srv_count', 'same_srv_rate', 'dst_host_diff_srv_rate',
       'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
       'dst_host_serror_rate', 'service_X11', 'service_Z39_50', 'service_auth',
       'service_bgp', 'service_courier', 'service_csnet_ns', 'service_ctf',
       'service_daytime', 'service_discard', 'service_domain',
       'service_domain_u', 'service_echo', 'service_eco_i', 'service_ecr_i',
       'service_efs', 'service_exec', 'service_finger', 'service_ftp',
       'service_ftp_data', 'service_gopher', 'service_hostnames',
       'service_http', 'service_http_443', 'service_imap4', 'service_iso_tsap',
       'service_klogin', 'service_kshell', 'service_ldap', 'service_link',
       'service_login', 'service_mtp', 'service_name', 'service_netbios_dgm',
       'service_netbios_ns', 'service_netbios_ssn', 'service_netstat',
       'service_nnsp', 'service_nntp', 'service_ntp_u', 'service_other',
       'service_pm_dump', 'service_pop_2', 'service_pop_3', 'service_printer',
       'service_private', 'service_red_i', 'service_remote_job', 'service_rje',
       'service_shell', 'service_smtp', 'service_sql_net', 'service_ssh',
       'service_sunrpc', 'service_supdup', 'service_systat', 'service_telnet',
       'service_tftp_u', 'service_tim_i', 'service_time', 'service_urh_i',
       'service_urp_i', 'service_uucp', 'service_uucp_path', 'service_vmnet',
       'service_whois', 'flag_REJ', 'flag_RSTO', 'flag_RSTOS0', 'flag_RSTR',
       'flag_S0', 'flag_S1', 'flag_S2', 'flag_S3', 'flag_SF', 'flag_SH']

mapping = {'ipsweep': 'Probe','satan': 'Probe','nmap': 'Probe','portsweep': 'Probe','saint': 'Probe','mscan': 'Probe',
        'teardrop': 'DoS','pod': 'DoS','land': 'DoS','back': 'DoS','neptune': 'DoS','smurf': 'DoS','mailbomb': 'DoS',
        'udpstorm': 'DoS','apache2': 'DoS','processtable': 'DoS',
        'perl': 'U2R','loadmodule': 'U2R','rootkit': 'U2R','buffer_overflow': 'U2R','xterm': 'U2R','ps': 'U2R',
        'sqlattack': 'U2R','httptunnel': 'U2R',
        'ftp_write': 'R2L','phf': 'R2L','guess_passwd': 'R2L','warezmaster': 'R2L','warezclient': 'R2L','imap': 'R2L',
        'spy': 'R2L','multihop': 'R2L','named': 'R2L','snmpguess': 'R2L','worm': 'R2L','snmpgetattack': 'R2L',
        'xsnoop': 'R2L','xlock': 'R2L','sendmail': 'R2L',
        'normal': 'Normal'
        }

no_threads = 1

# Function to connect to the SQLite database
def connect_db():
    return sqlite3.connect(app.config['DATABASE'], detect_types=sqlite3.PARSE_DECLTYPES)

# Function to create the user table
def create_table():
    with connect_db() as db:
        cursor = db.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                password TEXT NOT NULL
            )
        ''')

        # Insert admin users if not already present
        users_data = [('admin', 'admin'), ('user1', 'password1'), ('user2', 'password2')]
        for username, password in users_data:
            cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
            user = cursor.fetchone()
            if not user:
                hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
                cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))

        db.commit()

# Create the user table when the app starts
create_table()

# Home route (login page)
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Query the database to get the user
        with connect_db() as db:
            cursor = db.cursor()
            cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
            user = cursor.fetchone()

        # Check if the user exists and the password is correct
        if user and check_password_hash(user[2], password):
            # Store user information in the session
            session['user_id'] = user[0]
            session['username'] = user[1]

            return redirect(url_for('home'))
        else:
            return render_template('login.html', message='Invalid username or password')

    return render_template('login.html', message='')

# Home route (after successful login)
@app.route('/home')
def home():
    # Check if the user is logged in
    if 'user_id' in session:
        return render_template('home.html', username=session['username'])
    else:
        return redirect(url_for('login'))

# Logout route
@app.route('/logout')
def logout():
    # Clear the session data
    session.clear()
    return redirect(url_for('login'))

@app.route('/detectpage')
def detectpage():
    return render_template('form.html',selected_columns=selected_columns)

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/radar')
def radar():
    return render_template('radar.html')

@app.route('/ML_detect', methods=['GET', 'POST'])
def ML_detect():
        if request.method == 'POST':
            user_input = {}
            for column in selected_columns:
                user_input[column] = request.form[column]

            # Create a DataFrame from user input
            user_df = pd.DataFrame([user_input])
       
            # Apply label encoding for 'flag' and 'service'
            formdata_encoded = pd.get_dummies(user_df, columns=['service', 'flag'], drop_first=True)
            # Assuming X_train_encoded is your training data after encoding
            form_df_encoded = formdata_encoded.reindex(columns=X2_encoded, fill_value=0)

            # Make predictions
            prediction = model.predict(form_df_encoded)

            # Map the predicted label to the corresponding category
            mapped_prediction = prediction[0] if prediction[0] in mapping else 'Unknown'

            # Get the human-readable label
            result_label = mapping.get(mapped_prediction, 'Unknown')

            result = f"{result_label}"
            attack=f"{prediction[0]}"

            radar_url = url_for('radar')
            return redirect(radar_url + '?result=' + result + '&attack=' + attack + '&threads=' + str(no_threads))

@app.route('/filepredict', methods=['POST'])
def filepredict():
    if request.method == 'POST':
        # Get the uploaded file
        uploaded_file = request.files['file']

        if uploaded_file.filename != '':
            # Read the CSV file
            user_df = pd.read_csv(uploaded_file)

            # Apply label encoding for 'flag' and 'service'
            formdata_encoded = pd.get_dummies(user_df, columns=['service', 'flag'], drop_first=True)
            # Assuming X_train_encoded is your training data after encoding
            form_df_encoded = formdata_encoded.reindex(columns=X2_encoded, fill_value=0)

            # Make predictions
            predictions = model.predict(form_df_encoded)

            # Count the number of predictions not equal to 'normal'
            no_threads = sum(predictions != 'normal')

            # result = f"Total predictions: {len(predictions)}, Abnormal predictions: {abnormal_count}"

            radar_url = url_for('radar')
            return redirect(radar_url + '?threads=' + str(no_threads))
        # else:
        #     return render_template('result.html', result="No file uploaded.")

@app.route('/resultform')
def resultform():
    result = request.args.get('result')
    attack = request.args.get('attack')
    threads = int(request.args.get('threads'))

    if result=="Normal":
        return redirect('normal')
    elif threads==1:
        # return render_template('result.html', result=result, attack=attack)
        email_module.send_email(result, attack,threads)
        # attack_url = url_for('attack')
        return redirect(url_for('attack')+ '?thread=' + str(threads))
    else:
        email_module.send_email(0,0,threads)
        # return redirect(url_for('attack', thread=threads))
        return redirect(url_for('attack')+ '?thread=' + str(threads))

@app.route('/normal')
def normal():
    return render_template('Normal.html')

@app.route('/attack')
def attack():
    return render_template('Attack.html')

if __name__ == '__main__':
    app.run(debug=True)
