from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory, flash, make_response
import os
from werkzeug.utils import secure_filename
import os
from sqlalchemy.exc import IntegrityError
from encryption_utils import encrypt_file, decrypt_file, generate_key
from models import User, File, db
from config import Config
import jsonify

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()  # Get the user by username

        # Check if user exists and verify the password
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            return redirect(url_for('upload_file'))
        else:
            flash('Login failed. Check your credentials.')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

import base64

@app.route('/users', methods=['GET'])
def list_users():
    # Fetch all users from the database
    users = User.query.all()
    user_list = [{"id": user.id, "username": user.username, "password" : user.password}  for user in users]
    return {"users": user_list}, 200

@app.route('/files', methods=['GET'])
def list_files():
    # Fetch all users from the database
    files = File.query.all()
    files_list = [{"id": file.id, "user_id" : file.user_id ,"filename": file.filename, "encrypted_filename" : file.encrypted_filename, "encryption_key" : file.encryption_key}  for file in files]
    return {"files": files_list}, 200

@app.route('/files/<int:file_id>', methods=['DELETE'])
def del_file(file_id):
    # Get the file record from the database
    file_record = File.query.get_or_404(file_id)

    # Check if the user has permission to delete the file
    user_id = request.args.get('user_id')  # Assuming you pass user_id as a query parameter
    if file_record.user_id != int(user_id):
        return jsonify({"error": "You don't have permission to delete this file."}), 403

    # Delete the file record from the database
    db.session.delete(file_record)
    db.session.commit()

    return jsonify({"message": "File deleted successfully!"}), 200

@app.route('/delete_user/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    return {'message': 'User deleted successfully'}, 200

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Check if the username already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose a different one.')
            return redirect(url_for('register'))

        # Hash the password and create a new user
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! You can now log in.')
        return redirect(url_for('login'))

    return render_template('register.html')



@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        file = request.files['file']
        if file:
            filename = secure_filename(file.filename)
            file_data = file.read()

            # Check if filename is already taken
            if File.query.filter_by(filename=filename).first():
                flash('Filename already exists. Please rename your file and try again.')
                return redirect(url_for('upload_file'))

            # Encryption part
            key = generate_key()  # Generate a key to encrypt the file
            encrypted_data = encrypt_file(file_data, key)
            encrypted_filename = filename + ".enc"

            # Save encrypted file
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], encrypted_filename)
            with open(file_path, 'wb') as f:
                f.write(encrypted_data)

            # Encode the key in Base64 for storage
            encoded_key = base64.b64encode(key).decode('utf-8')

            # Save file record in the database with the encoded encryption key
            new_file = File(
                filename=filename,
                encrypted_filename=encrypted_filename,
                user_id=session['user_id'],
                encryption_key=encoded_key  # Store the encoded key
            )

            try:
                db.session.add(new_file)
                db.session.commit()
                flash('File uploaded and encrypted successfully!')
            except IntegrityError:
                db.session.rollback()
                flash('Filename already exists. Please rename your file and try again.')
                return redirect(url_for('upload_file'))

    # Query to get user files
    user_files = File.query.filter_by(user_id=session['user_id']).all()
    
    return render_template('upload.html', user_files=user_files)



@app.route('/download/<int:file_id>', methods=['GET'])
def download_file(file_id):
    # Get the file record from the database
    file_record = File.query.get_or_404(file_id)

    # Check if the user has permission to download the file
    if file_record.user_id != session['user_id']:
        flash("You don't have permission to access this file.")
        return redirect(url_for('upload_file'))

    # Path to the encrypted file
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_record.encrypted_filename)
    
    # Read the encrypted data
    with open(file_path, 'rb') as f:
        encrypted_data = f.read()

    # Decode the key from Base64
    key = base64.b64decode(file_record.encryption_key)

    # Decrypt the file
    decrypted_data = decrypt_file(encrypted_data, key)

    # Serve the decrypted data
    response = make_response(decrypted_data)
    response.headers['Content-Disposition'] = f'attachment; filename={file_record.filename}'
    response.headers['Content-Type'] = 'application/octet-stream'
    
    return response


@app.route('/delete/<int:file_id>', methods=['POST'])
def delete_file(file_id):
    # Get the file record from the database
    file_record = File.query.get_or_404(file_id)

    # Check if the user has permission to delete the file
    if file_record.user_id != session['user_id']:
        flash("You don't have permission to delete this file.")
        return redirect(url_for('upload_file'))

    # Path to the encrypted file
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_record.encrypted_filename)

    # Delete the file from the upload folder
    if os.path.exists(file_path):
        os.remove(file_path)  # Remove the file from the filesystem

    # Delete the file record from the database
    db.session.delete(file_record)
    db.session.commit()

    flash('File deleted successfully!')
    return redirect(url_for('upload_file'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create the tables before the app starts running
    app.run(debug=True)