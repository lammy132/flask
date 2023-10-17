from flask import Flask
from flask import render_template
from flask import request
from flask import flash
from flask import redirect
from flask import url_for
from flask import session
import os
import random
import string
import logging
from flask import request, jsonify
from sqlalchemy.exc import IntegrityError
import traceback
from decimal import Decimal
from sqlalchemy.sql.functions import user
from tronapi import Tron
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime
from flask_migrate import Migrate
import threading
import time
from sqlalchemy import func
from tronpy import Tron
from tronpy.keys import PrivateKey
from sqlalchemy.exc import IntegrityError
from wtforms import FloatField, StringField, SubmitField
from wtforms.validators import DataRequired, NumberRange
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
import requests
from flask_wtf import FlaskForm
from tronpy.exceptions import AddressNotFound
from tronapi import Tron, HttpProvider
import sys
import hashlib
import base58
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)



app.secret_key= b'H\xb0?\r\xce \xd7\x9aG\xca:vtj\xab\x16\x91\n\x84\x93\xc9!\xe5\x90'

scheduler = BackgroundScheduler()

db = SQLAlchemy()

app.config['SECRET_KEY'] = b'H\xb0?\r\xce \xd7\x9aG\xca:vtj\xab\x16\x91\n\x84\x93\xc9!\xe5\x90'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://m7136_James107:Jakehicks1840@mysql0.serv00.com/m7136_randcryptos'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

# Initialize Tron instance
tron = Tron()

migrate = Migrate(app, db)
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)



# Define the WithdrawalRequest model
class WithdrawalRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', back_populates='withdrawal_requests')
    amount = db.Column(db.Float, nullable=False)
    wallet_address = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), default='Pending')
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    
class TransactionHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', back_populates='transaction_history')
    crypto_asset = db.Column(db.String(50), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    transaction_id = db.Column(db.String(255))

    
# Define the User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    balance = db.Column(db.Float, default=0.0)
    tron_address = db.Column(db.String(50), unique=True, nullable=False)
    tron_private_key = db.Column(db.String(256))
    withdrawal_requests = db.relationship('WithdrawalRequest', back_populates='user')
    is_admin = db.Column(db.Boolean, default=False)
    transaction_history = db.relationship('TransactionHistory', back_populates='user')
    referral_code = db.Column(db.String(6), unique=True, nullable=True)  # Add this field
    referred_by_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    referred_by = db.relationship('User', remote_side=[id])
    referral_count = db.Column(db.Integer, default=0)
    email = db.Column(db.String(120), unique=True, nullable=False)

# Define the Investment model
class Investment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    crypto_asset = db.Column(db.String(50), nullable=False)
    amount_invested = db.Column(db.Float, nullable=False)
    current_value = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

# Define the Transaction model
class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    crypto_asset = db.Column(db.String(50), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# Define the Admin model
class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

# Define the WithdrawalForm class
class WithdrawalForm(FlaskForm):
    amount = FloatField('Withdrawal Amount (USDT)', validators=[
        DataRequired(message='This field is required'),
        NumberRange(min=1, message='Withdrawal amount must be greater than 0')
    ])
    wallet_address = StringField('Withdrawal Wallet Address', validators=[
        DataRequired(message='This field is required')
    ])
    submit = SubmitField('Submit')

# Define the InvestmentForm class
class InvestmentForm(FlaskForm):
    investment = FloatField(
        'Investment Amount (USDT)',
        validators=[
            DataRequired(message='This field is required'),
            NumberRange(min=1, message='Minimum investment amount is 100 USDT')
        ]
    )
    submit = SubmitField('Invest')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Initialize Tron instance
tron = Tron()

# Initialize the BackgroundScheduler
scheduler = BackgroundScheduler(daemon=True)
scheduler.start()

central_wallet_address = 'TLuEzjFP6ju688nhnKjwy4UZKCCY4F6Cqo'



def base58check_to_hexstring(base58addr):
    try:
        # Check if the input is already in hexadecimal format
        if all(c in '0123456789abcdefABCDEF' for c in base58addr):
            return base58addr

        # Decode the Base58 address
        data = base58.b58decode(base58addr)

        # Extract the address (excluding the checksum)
        address = data[:-4]

        hex_address = address.hex()

        return hex_address
    except Exception as e:
        logging.error(f"Error converting address: {e}")
        return None

  # Import the traceback module


# Define the TronGrid API base URL
tron_grid_base_url = "https://api.trongrid.io/v1"

def calculate_current_usdt_balance(user_wallet_address):
    try:
        # Construct the API URL to get TRC-20 transactions for the user's wallet address
        api_url = f'{tron_grid_base_url}/accounts/{user_wallet_address}/transactions/trc20'
        response = requests.get(api_url)

        if response.status_code == 200:
            transactions = response.json().get('data')

            # Initialize the current USDT balance as 0
            current_usdt_balance = 0

            if transactions:
                for tx in transactions:
                    # Extract the amount from the transaction data
                    transaction_amount = int(tx['value'])  # Convert from SUN to USDT
                    current_usdt_balance += transaction_amount

            # Update the user's balance in the database
            user = User.query.filter_by(tron_address=user_wallet_address).first()
            if user:
                user.balance = current_usdt_balance / 1000000  # Convert from SUN to USDT
                db.session.commit()  # Commit the update to the database

            return current_usdt_balance
        else:
            # Handle the case where the API request fails
            return None
        logging.info (f" API Failure")
    except Exception as e:
        # Handle any exceptions that may occur during API request or data processing
        return None


def get_total_usdt_received(user_wallet_address):
    try:
        # Log the input
        logging.info(f"Checking USDT transactions for user_wallet_address: {user_wallet_address}")

        # Construct the API URL to get TRC-20 transactions for the user's wallet address
        api_url = f'{tron_grid_base_url}/accounts/{user_wallet_address}/transactions/trc20'
        response = requests.get(api_url)

        if response.status_code == 200:
            transactions = response.json().get('data')
            if transactions:
                total_usdt_received = 0

                for tx in transactions:
                    # Extract the amount from the transaction data
                    transaction_amount = int(tx['value']) # Convert from SUN to USDT
                    total_usdt_received += transaction_amount

                return total_usdt_received
            else:
                logging.warning(f"No USDT transactions found for {user_wallet_address}")
        else:
            logging.error(f"Error fetching USDT transaction data for {user_wallet_address}: {response.text}")

        return 0
    except requests.exceptions.RequestException as e:
        # Handle network-related errors
        logging.error(f"Network error while checking USDT transactions for {user_wallet_address}: {e}")
        return 0
    except Exception as e:
        # Log the exception
        logging.error(f"Error checking USDT transactions for {user_wallet_address}: {e}")
        return 0

def update_investments_for_all_users():
    try:
        # Get all users from the database
        users = User.query.all()

        for user in users:
            user_wallet_address = user.tron_address
            hex_address = base58check_to_hexstring(user_wallet_address)
           
            if hex_address:
                # Retrieve the total USDT amount received by the user's wallet address
                total_usdt_received = get_total_usdt_received(user_wallet_address)
                
                if total_usdt_received >= 1000000:  # Check for transactions >= 1 USDT
                    # Check if the user has a previous investment with the same amount
                    previous_investment = Investment.query.filter_by(
                        user_id=user.id,
                        crypto_asset="USDT",
                        amount_invested=total_usdt_received / 1000000  # Convert to USDT
                    ).first()
                    
                    if previous_investment:
                        # Investment with the same amount already exists, skip
                        continue

                    # Calculate the current value based on the user's balance
                    current_balance = user.balance * 1000000  # Convert from USDT to SUN
                    current_value = current_balance - total_usdt_received

                    # Create a new investment record
                    new_investment = Investment(
                        user_id=user.id,
                        crypto_asset="USDT",
                        amount_invested=total_usdt_received / 1000000,  # Convert to USDT
                        current_value=current_value / 1000000,  # Convert to USDT
                        timestamp=datetime.utcnow()
                    )

                    db.session.add(new_investment)
                    db.session.commit()

    except Exception as e:
        # Handle any exceptions here
        logging.error(f"Error updating investments for all users: {e}")



def update_user_investment(user_wallet_address, tx_amount):
    user = User.query.filter_by(tron_address=user_wallet_address).first()
    
    if user:
        # Convert the user's balance to Decimal
        user.balance = Decimal(str(user.balance))
        
        # Convert the transaction amount to Decimal
        tx_amount = Decimal(str(tx_amount))
        
        # Check if a transaction with the same amount and wallet address exists
        existing_transaction = TransactionHistory.query.filter_by(
            user_id=user.id,
            amount=tx_amount / 1000000,  # Convert to TRX for storage
        ).first()
        
        if not existing_transaction:
            user.balance += tx_amount / 1000000  # Convert from SUN to USDT
            
            # Add the new transaction to the TransactionHistory
            transaction = TransactionHistory(
                user_id=user.id,
                crypto_asset="USDT",  # Replace with the actual crypto asset
                amount=tx_amount / 1000000,  # Convert to TRX for storage
                timestamp=datetime.utcnow(),
            )
            
            db.session.add(transaction)
            db.session.commit()
            logging.info(f"USDT Balance added to user {user.username}. New balance: {user.balance:.3f}")
        else:
            logging.warning("Transaction already exists, not adding a duplicate entry.")
    else:
        logging.warning("User not found.")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        referral_code = request.form['referral_code']  # Get the referral code from the form
        email = request.form['email']

        # Check if the username already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose a different username.', 'danger')
            return redirect(url_for('register'))

        # Generate a new private key using tronpy
        private_key = PrivateKey.random()

        # Get the corresponding public key
        public_key = private_key.public_key.to_base58check_address()

        # Get the private key as a hex string
        private_key_hex = private_key.hex()
        generated_referral_code = generate_referral_code()
        email=email

        # Create a new user and insert into the database
        user = User(username=username, password=password, balance=0.0, tron_address=public_key, tron_private_key=private_key_hex, referral_code=generated_referral_code, email=email)


        # Check if a valid referral code is provided
        if referral_code:
            referrer = User.query.filter_by(referral_code=referral_code).first()
            if referrer:
                # Set referred_by_id to the ID of the referrer
                user.referred_by_id = referrer.id

        try:
            db.session.add(user)
            db.session.commit()
            flash('Registration successful', 'success')
            return redirect(url_for('login'))
        except IntegrityError:
            db.session.rollback()
            flash('Username already exists. Please choose a different username.', 'danger')
            return redirect(url_for('register'))
    
    return render_template('register.html')

@app.route('/referral/<string:referral_code>')
def referral(referral_code):
    # Add logic to handle referral code here...
    return f"Referral Page for code: {referral_code}"


def generate_referral_code():
    while True:
        code = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(6))
        existing_user = User.query.filter_by(referral_code=code).first()
        if not existing_user:
            return code



@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        admin = Admin.query.filter_by(username=username, password=password).first()
        if admin:
            session['admin_id'] = admin.id
            flash('Admin login successful', 'success')
            return redirect(url_for('admin_withdrawals'))
        else:
            flash('Admin login failed. Please check your credentials.', 'danger')
    return render_template('adminlogin.html')

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_id', None)
    flash('Admin logged out', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    user_balance = current_user.balance
    user_transaction_history = TransactionHistory.query.filter_by(user_id=current_user.id).all()  # Retrieve transaction history  # Retrieve transaction history
    total_investment_amount = db.session.query(func.sum(Investment.amount_invested)).filter_by(user_id=current_user.id).scalar()
    withdrawal_requests = WithdrawalRequest.query.filter_by(user_id=current_user.id).all()
    form = InvestmentForm()
    investment_portfolio = Investment.query.filter_by(user_id=current_user.id).all()

    return render_template('dashboard.html', user=current_user, user_balance=user_balance,
                           user_transaction_history=user_transaction_history, form=form, total_investment_amount=total_investment_amount,
                           investments=investment_portfolio, withdrawal_requests=withdrawal_requests)

@app.route('/withdrawal', methods=['GET', 'POST'])
@login_required
def withdrawal():
    form = WithdrawalForm()
    if form.validate_on_submit():
        amount = form.amount.data
        wallet_address = form.wallet_address.data

        withdrawal_request = WithdrawalRequest(
            user_id=current_user.id,
            amount=amount,
            wallet_address=wallet_address
        )

        db.session.add(withdrawal_request)
        db.session.commit()

        flash('Withdrawal request submitted successfully', 'success')
        return redirect(url_for('dashboard'))

    return render_template('withdrawal.html', form=form)

@app.route('/admin/withdrawals')
@login_required
def admin_withdrawals():
    if 'admin_id' in session:
        withdrawal_requests = WithdrawalRequest.query.all()
        return render_template('admin_withdrawals.html', withdrawal_requests=withdrawal_requests)
    else:
        flash('Admin login required', 'danger')
        return redirect(url_for('admin_login'))

@app.route('/admin/approve_withdrawal/<int:withdrawal_id>')
@login_required
def approve_withdrawal(withdrawal_id):
    withdrawal_request = WithdrawalRequest.query.get(withdrawal_id)
    if withdrawal_request:
        withdrawal_request.status = 'Approved'

        user = User.query.get(withdrawal_request.user_id)
        if user:
            user.balance -= withdrawal_request.amount

        db.session.commit()
        flash('Withdrawal request approved', 'success')
    else:
        flash('Withdrawal request not found', 'danger')
    return redirect(url_for('admin_withdrawals'))

@app.route('/admin/reject_withdrawal/<int:withdrawal_id>')
@login_required
def reject_withdrawal(withdrawal_id):
    withdrawal_request = WithdrawalRequest.query.get(withdrawal_id)
    if withdrawal_request:
        withdrawal_request.status = 'Rejected'
        db.session.commit()
        flash('Withdrawal request rejected', 'success')
    else:
        flash('Withdrawal request not found', 'danger')
    return redirect(url_for('admin_withdrawals'))


def get_authenticated_user():
    # Check if the current user is authenticated using Flask-Login
    if current_user.is_authenticated:
        # Return the authenticated user, which should have a 'tron_address' attribute
        return current_user
    else:
        return None  # No authenticated user
# ...

@app.route('/invest', methods=['POST', 'GET'])
def invest():
    if request.method == 'POST':
        amount_usdt = Decimal(request.form['investment'])  # Use Decimal for precise handling of currency
        amount_sun = amount_usdt * 1000000  # Convert USDT to sun (TRX)

        if amount_sun >= 101 * 1000000:  # Make sure it's at least 1 TRX worth
            # Perform user authentication, obtain user object, and check the user's wallet address
            user = get_authenticated_user()  # Implement the authentication logic

            if user:
                user_wallet_address = user.tron_address
                if user_wallet_address:
                    if check_usdt_transaction(user_wallet_address, amount_sun):
                        crypto_asset = "USDT"
                        
                        # Check for duplicate investments by user, crypto asset, and amount with different timestamps
                        existing_investment = Investment.query.filter_by(
                            user_id=user.id,
                            crypto_asset=crypto_asset,
                            amount_invested=amount_sun / 1000000,  # Convert to TRX
                        ).first()

                        if existing_investment:
                            flash('Investment with the same amount already exists. You can make another investment.', 'info')
                        else:
                            investment = Investment(
                                user_id=user.id,
                                crypto_asset=crypto_asset,
                                amount_invested=amount_sun / 1000000,
                                timestamp=datetime.utcnow()
                            )
                            db.session.add(investment)
                            db.session.commit()
                            flash(f'Investment of {amount_usdt} USDT in {crypto_asset} successful', 'success')
                            logging.info(f"Investment of {amount_usdt} USDT in {crypto_asset} successful for {user_wallet_address}")
                    else:
                        flash('Investment failed. Transaction not sent to your wallet address.', 'danger')
                        logging.warning(f"Investment failed for {user_wallet_address}")
                else:
                    flash('Invalid TRON wallet address format', 'danger')
            else:
                flash('User not authenticated', 'danger')
        else:
            flash('Minimum investment amount is 1 USDT (1,000,000 sun)', 'danger')

    return redirect(url_for('dashboard'))


def check_usdt_transaction(user_wallet_address, tx_amount):
    try:
        logging.info(f"Checking USDT transaction for user_wallet_address: {user_wallet_address}")
        hex_address = user_wallet_address  # Use the provided wallet address directly

        if hex_address:
            api_url = f'{tron_grid_base_url}/accounts/{hex_address}/transactions/trc20'
            response = requests.get(api_url)

            if response.status_code == 200:
                transactions = response.json().get('data')

                if transactions:
                    for tx in transactions:
                        transaction_value = int(tx.get('value', 0))
                        if transaction_value >= tx_amount:
                            update_user_investment(user_wallet_address, transaction_value)
                            logging.info(f"USDT Transaction checked and verified for {user_wallet_address}")

                else:
                    logging.warning(f"No USDT transactions found for {user_wallet_address}")
            else:
                logging.error(f"Error fetching USDT transaction data for {user_wallet_address}: {response.text}")

        return False
    except requests.exceptions.RequestException as e:
        logging.error(f"Network error while checking USDT transaction for {user_wallet_address}: {e}")
        return False
    except Exception as e:
        logging.error(f"Error checking USDT transaction for {user_wallet_address}: {e}")
        return False


def update_user_investment(user_wallet_address, tx_amount):
    user = User.query.filter_by(tron_address=user_wallet_address).first()
    
    if user:
        # Convert the user's balance to Decimal
        user.balance = Decimal(str(user.balance))
        
        # Convert the transaction amount to Decimal
        tx_amount = Decimal(str(tx_amount))
        
        # Check if a transaction with the same amount and wallet address exists
        existing_transaction = TransactionHistory.query.filter_by(
            user_id=user.id,
            amount=tx_amount / 1000000,  # Convert to TRX for storage
        ).first()
        
        if not existing_transaction:
            user.balance += tx_amount / 1000000  # Convert from SUN to USDT
            
            # Add the new transaction to the TransactionHistory
            transaction = TransactionHistory(
                user_id=user.id,
                crypto_asset="USDT",  # Replace with the actual crypto asset
                amount=tx_amount / 1000000,  # Convert to TRX for storage
                timestamp=datetime.utcnow(),
            )
            
            db.session.add(transaction)
            db.session.commit()
            logging.info(f"USDT Balance added to user {user.username}. New balance: {user.balance:.3f}")
        else:
            logging.warning("Transaction already exists, not adding a duplicate entry.")
    else:
        logging.warning("User not found.")



def update_user_balance():
    try:
        users = User.query.all()

        for user in users:
            logging.info(f"Processing user: {user.username}, referral_count: {user.referral_count}")
            if user_has_referrals(user):
                referral_bonus_percentage = calculate_referral_bonus_percentage(user)
                daily_increase = user.balance * (referral_bonus_percentage + 0.5) / 100
            else:
                daily_increase = user.balance * 2 / 100
                logging.info(f"Daily increase for user {user.username}: {daily_increase}")

            daily_increase = round(daily_increase, 3)

            try:
                user.balance += daily_increase
                db.session.commit()
                logging.info(f"USDT Balance added to user {user.username}. New balance: {user.balance:.3f}")
            except IntegrityError:
                db.session.rollback()
                logging.warning(f"Concurrent update detected for user {user.username}. Retrying...")

    except Exception as e:
        logging.error(f"Error updating balance: {e}")

# ...


# ...

def user_has_referrals(user):
    # Check if the user's referred_by_id is not None
    return user.referred_by_id is not None



        
scheduler.add_job(update_user_balance, CronTrigger(hour=0))  # Run daily at midnight
def calculate_referral_bonus_percentage(user):
    # User A gets a 2.5% base bonus
    bonus_percentage = 2.5

    if user.referral_count is not None:
        # Calculate additional bonus based on referrals
        if user.referral_count >= 10:
            additional_bonus = (user.referral_count // 10) * 0.5
            bonus_percentage += additional_bonus

    return bonus_percentage


        
@app.route('/update_balance_manually', methods=['POST','GET'])
@login_required  # Make sure only authenticated users can trigger this route
def update_balance_manually():
    if current_user.is_admin:  # Check if the current user is an admin
        try:
            update_user_balance()  # Call the update_user_balance function

            # Return a success message as JSON response
            return jsonify({'message': 'Balance updated successfully'}), 200

        except Exception as e:
            # Handle any exceptions here and return an error message as JSON response
            return jsonify({'error': f'Error updating balance: {str(e)}'}), 500

    else:
        # If the current user is not an admin, return a permission denied message as JSON response
        return jsonify({'error': 'Permission denied'}), 403
# Modify your BackgroundScheduler to run the update_user_balance function daily
  # Import IntegrityError
# Update user USDT transaction history for a single user
def update_usdt_transaction_history_for_user(user):
    try:
        user_wallet_address = user.tron_address
        hex_address = base58check_to_hexstring(user_wallet_address)
        
        if hex_address:
            api_url = f'https://api.trongrid.io/v1/accounts/{hex_address}/transactions/trc20'
            response = requests.get(api_url)

            if response.status_code == 200:
                transactions = response.json().get('data')

                if transactions:
                    for tx in transactions:
                        crypto_asset = "USDT"  # Replace with the actual crypto asset you are tracking
                        transaction_id = tx.get('transaction_id')

                        # Check if the transaction already exists in the database
                        existing_transaction = TransactionHistory.query.filter_by(
                            user_id=user.id,
                            crypto_asset=crypto_asset,
                            transaction_id=transaction_id
                        ).first()

                        if not existing_transaction:
                            amount = int(tx.get('value', '0'))
                            # Create a new transaction history record
                            transaction = TransactionHistory(
                                user_id=user.id,
                                crypto_asset=crypto_asset,
                                amount=amount / 1000000,  # Convert to TRX for storage
                                timestamp=datetime.utcfromtimestamp(int(tx.get('block_timestamp') / 1000)),  # Convert to UTC
                                transaction_id=transaction_id  # Store the transaction ID
                            )

                            # Add the new transaction history record to the database
                            db.session.add(transaction)

                            try:
                                db.session.commit()
                            except IntegrityError:
                                db.session.rollback()  # Handle possible IntegrityError (e.g., duplicate entries)

    except Exception as e:
        # Handle any exceptions here
        logging.error(f"Error updating USDT transaction history for {user.tron_address}: {e}")

# Update USDT transaction history for all users
def update_usdt_transaction_history_for_all_users():
    try:
        # Get all users from the database
        users = User.query.all()

        for user in users:
            update_usdt_transaction_history_for_user(user)
    
    except Exception as e:
        # Handle any exceptions here
        logging.error(f"Error updating USDT transaction history for all users: {e}")

# ... (other routes and code)

# Create an instance of BackgroundScheduler
# Create a wrapper function to call update_usdt_transaction_history_for_user
def update_usdt_transaction_wrapper():
    # Get all users from the database
    users = User.query.all()

    for user in users:
        update_usdt_transaction_history_for_user(user)

# Add the wrapper function to the scheduler


@app.route('/update_usdt_transaction_history_manually', methods=['POST', 'GET'])
@login_required  # Make sure only authenticated users can trigger this route
def update_usdt_transaction_history_manually():
    if current_user.is_admin:  # Check if the current user is an admin
        try:
            update_usdt_transaction_history_for_all_users()  # Call the updated function for all users

            # Return a success message as JSON response
            return jsonify({'message': 'USDT transaction history updated successfully'}), 200

        except Exception as e:
            # Handle any exceptions here and return an error message as JSON response
            return jsonify({'error': f'Error updating USDT transaction history: {str(e)}'}), 500

    else:
        # If the current user is not an admin, return a permission denied message as JSON response
        return jsonify({'error': 'Permission denied'}), 403






@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.password == password:
            login_user(user)
            flash('Login successful', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Login failed. Please check your username and password.', 'danger')
    return render_template('login.html')

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))
@app.route('/contact')
def contact_us():
    return render_template('contact.html')
@app.route('/team')
def team():
    return render_template('team.html')
@app.route('/aboutus')
def about_us():
    return render_template('aboutus.html')
@app.route('/Currency')
def Currency():
    return render_template('Currency.html')


   

if __name__ == '__main__':
  with app.app_context():
    # Now you're within the Flask application context
    # Perform your database operations or other Flask-specific tasks here
    logging.info("This is logged within the Flask application context")
    scheduler.add_job(update_user_balance, CronTrigger(hour=0))
    scheduler.add_job(update_usdt_transaction_wrapper, 'interval', minutes=5)
    scheduler.add_job(update_investments_for_all_users, 'interval', seconds=120)
    # Start the scheduler
  if not scheduler.running:
    scheduler.start()

    scheduler.start()
    db.create_all()
    logging.basicConfig(filename='app.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    app.run(debug=True)
