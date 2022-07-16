"""
    This script will start a server that takes in user input (item and quantity)
    and adds to database. User can also see a list of orders pending.
"""
import datetime
import os
import logging
import time
from functools import wraps
import secrets
from sys import stdout
from flask import Flask, render_template, request, jsonify, redirect
from werkzeug.security import generate_password_hash, check_password_hash
import psycopg2
import jwt
import redis

LOGGER = logging.getLogger()
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
LOGGER.setLevel(LOG_LEVEL)
consoleHandler = logging.StreamHandler(stdout)
LOGGER.addHandler(consoleHandler)

USERNAME = 'postgres'
PASSWORD = 'postgres'
HOST = 'postgres'
DB = 'emporiocafe'
PORT = 5432
APP_PORT = int(os.environ.get("PORT", 5000))
MAX_TOKEN = 3   # 3 hits / second

INSERT_ROW_QUERY = """
    INSERT INTO ORDERS (CUSTOMER_ID, ITEM, QTY)
    VALUES ('{customer_id}', '{item}', '{qty}');
"""
GET_PENDING_ORDERS_QUERY = """
    SELECT * FROM ORDERS
    WHERE CUSTOMER_ID = '{customer_id}';
"""
GET_CUSTOMER_BY_CID_QUERY = """
    SELECT * FROM CUSTOMERS
    WHERE CUSTOMER_ID = '{customer_id}';
"""
INSERT_NEW_CUSTOMER_QUERY = """
    INSERT INTO CUSTOMERS (CUSTOMER_ID, HASHED_PASSWD)
    VALUES ('{customer_id}', '{hashed_passwd}');
"""

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_urlsafe(20)
SECRET = app.config['SECRET_KEY']


def set_value_in_cache(r, key, value):
    try:
        r.set(key, value)
        LOGGER.info("Successfully added")
    except redis.exceptions as err:
        LOGGER.error(err)
        raise err


def get_value_from_cache(r, ip_addr):
    value = None
    try:
        value = r.get(ip_addr)
        LOGGER.info("Successfully retrieved from cache")
    except redis.exceptions as err:
        LOGGER.error(err)
        raise err
    return value


def rate_limiter(func):
    """
    This is a decorator function used to throttle APIs
    :param func: Function that has to be decorated
    :return: Decorated function
    """
    @wraps(func)
    def decorated(*args, **kwargs):
        LOGGER.info("Initiating connection with redis...")
        r = None
        try:
            r = redis.Redis(
                host='redis',
                port=6379
            )
            LOGGER.info("Connected to redis")
        except redis.exceptions as err:
            LOGGER.error(err)
            raise err
        ip_addr = request.remote_addr
        LOGGER.info('Client IP: ' + ip_addr)
        if not get_value_from_cache(r, ip_addr):
            # put timestamp and max tokens
            LOGGER.info("Adding new entry in cache")
            value = str(time.time()) + ',' + str(MAX_TOKEN - 1)
            set_value_in_cache(r, ip_addr, value)
        else:
            # get current tokens left
            LOGGER.info("Fetching last record for client IP in cache...")
            value = get_value_from_cache(r, ip_addr).decode("utf-8")
            last_time, tokens = float(value.split(',')[0]), int(value.split(',')[1])
            LOGGER.info('Last time: ' + str(last_time))
            LOGGER.info('Tokens: ' + str(tokens))
            time_now = time.time()
            if time_now >= last_time + 1:
                LOGGER.info(f"Client has sufficient tokens to hit API; Remaining tokens: {MAX_TOKEN - 1}")
                value = str(time_now) + ',' + str(MAX_TOKEN - 1)
                set_value_in_cache(r, ip_addr, value)
            elif tokens > 0:
                LOGGER.info(f"Client has sufficient tokens to hit API; Remaining tokens: {tokens - 1}")
                value = str(last_time) + ',' + str(tokens - 1)
                set_value_in_cache(r, ip_addr, value)
            else:
                LOGGER.info("Client doesn't have sufficient tokens to hit API")
                return jsonify({"message": "Too many requests"}), 429
        return func(*args, **kwargs)
    return decorated


def token_required(func):
    """
    This is a decorator function used to check if token is valid.
    :param func: Function that has to be decorated
    :return: Decorated function
    """
    @wraps(func)
    def decorated(*args, **kwargs):
        token = None
        if 'token' in request.args:
            token = request.args['token']
        if not token:
            return jsonify({"message": "Token not found"}), 401
        try:
            data = jwt.decode(token, SECRET, algorithms=["HS256"])
            customer_id = data['cid']
        except jwt.exceptions.InvalidTokenError:
            return jsonify({"message": "Token invalid"}), 401
        return func(customer_id, *args, **kwargs)
    return decorated


def connect_to_db():
    """
    This function is used to connect to POSTGRES database
    :return: connection object and cursor object
    """
    conn = cursor = None
    LOGGER.info("Connecting to database...")
    try:
        conn = psycopg2.connect(user=USERNAME,
                                password=PASSWORD,
                                host=HOST,
                                port=PORT,
                                database=DB)
        cursor = conn.cursor()
        LOGGER.info("Connection established with DB")
    except psycopg2.OperationalError as err:
        LOGGER.error(err)
        raise err
    except psycopg2.InternalError as err:
        LOGGER.error(err)
        raise err
    except psycopg2.DataError as err:
        LOGGER.error(err)
        raise err
    return conn, cursor


def add_order_to_db(conn, cursor, customer_id, item, qty):
    """
    This function is used to add a new row to database consisting of
    customer_id, item and qty
    :param conn: connection object
    :param cursor: cursor object
    :param customer_id: customer id
    :param item: item name
    :param qty: quantity (string)
    :return: Success message
    """
    LOGGER.info("Adding new order to database")
    try:
        cursor.execute(INSERT_ROW_QUERY.format(customer_id=customer_id, item=item, qty=qty))
        conn.commit()
        LOGGER.info("Added order to database successfully")
    except psycopg2.OperationalError as err:
        LOGGER.error(err)
        raise err
    except psycopg2.InternalError as err:
        LOGGER.error(err)
        raise err
    except psycopg2.DataError as err:
        LOGGER.error(err)
        raise err
    return "Added successfully"


def customer_id_exists(cursor, customer_id):
    """
    This function checks if any there's any entry in customer table with given customer ID.
    If there exists, it returns the row as well.
    :param cursor: cursor object
    :param customer_id: customer_id for which check is going to be performed
    :return: True and respective row if customer_id is present otherwise False
    """
    response = None
    LOGGER.info("Checking if customer exists already")
    try:
        cursor.execute(GET_CUSTOMER_BY_CID_QUERY.format(customer_id=customer_id))
        response = cursor.fetchall()
        LOGGER.info("Check operation successful")
    except psycopg2.OperationalError as err:
        LOGGER.error(err)
        raise err
    except psycopg2.InternalError as err:
        LOGGER.error(err)
        raise err
    except psycopg2.DataError as err:
        LOGGER.error(err)
        raise err
    if len(response) == 0:
        LOGGER.info("Customer doesn't exist")
        return False, None
    LOGGER.info("Customer already exists")
    return True, response


def close_connection(conn, cursor):
    """
    This function is used to close DB connection
    :param conn: connection object
    :param cursor: cursor object
    :return: Void function
    """
    LOGGER.info("Closing connection...")
    try:
        cursor.close()
        conn.close()
        LOGGER.info("Connection terminated successfully")
    except psycopg2.OperationalError as err:
        LOGGER.error(err)
        raise err
    except psycopg2.InternalError as err:
        LOGGER.error(err)
        raise err
    except psycopg2.DataError as err:
        LOGGER.error(err)
        raise err


@app.route("/")
@rate_limiter
def index():
    """
    This is the home page which redirects to sign up page upon being hit
    :return: sign up html template
    """
    LOGGER.info("Index page hit")
    return redirect("/signup")


@app.route("/order", methods=["GET"])
@token_required
@rate_limiter
def order(cid):
    """
    This function returns submit order page
    :return: submit-order.html from templates
    """
    LOGGER.info("Orders page hit")
    token = request.args['token']
    return render_template("submit-order.html", cid=cid, token=token)


@app.route("/signup")
@rate_limiter
def signup():
    """
    This is the sign up page
    :return: sign up html page
    """
    LOGGER.info("Sign up page hit")
    return render_template('sign-up.html', error=False)


@app.route("/login")
@rate_limiter
def login():
    """
        This is the log in page
        :return: log in html page
    """
    LOGGER.info("Log in page hit")
    return render_template('log-in.html')


@app.route("/submit_sign_up", methods=["POST"])
@rate_limiter
def submit_sign_up_request():
    """
    This function is used to submit sign up request to be able to access
    order section
    :return: order html template
    """
    cid = request.form['cid']
    passwd = request.form['passwd']
    conn, cursor = connect_to_db()
    customer_id_in_table, record = customer_id_exists(cursor, cid)
    if customer_id_in_table:
        close_connection(conn, cursor)
        LOGGER.error("Customer ID already exists")
        return render_template('sign-up.html', error=True)
    hashed_passwd = generate_password_hash(passwd)
    try:
        LOGGER.info("Adding customer to database")
        cursor.execute(INSERT_NEW_CUSTOMER_QUERY.format(customer_id=cid,
                                                        hashed_passwd=hashed_passwd))
        conn.commit()
        LOGGER.info("Customer added to database successfully")
    except psycopg2.OperationalError as err:
        LOGGER.error(err)
        raise err
    except psycopg2.InternalError as err:
        LOGGER.error(err)
        raise err
    except psycopg2.DataError as err:
        LOGGER.error(err)
        raise err
    close_connection(conn, cursor)
    payload = {
        'cid': cid,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=15)
    }
    token = None
    try:
        token = jwt.encode(payload, SECRET, algorithm='HS256')
        LOGGER.info("Token generated successfully")
    except jwt.exceptions as err:
        LOGGER.error(err)
        raise err
    redirect_url = f"/order?token={token}"
    return redirect(redirect_url)


@app.route("/submit_log_in", methods=["POST"])
@rate_limiter
def submit_log_in_request():
    """
    This function is used to submit log in request to be able to access
    order section
    :return: order html template
    """
    cid = request.form['cid']
    passwd = request.form['passwd']
    conn, cursor = connect_to_db()
    customer_id_in_table, record = customer_id_exists(cursor, cid)
    if not customer_id_in_table:
        LOGGER.error("Customer doesn't exist")
        close_connection(conn, cursor)
        return render_template('log-in.html', error=True)
    if not check_password_hash(record[0][1], passwd):
        return jsonify({"message": "Wrong password"}), 401
    close_connection(conn, cursor)
    payload = {
        'cid': cid,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=15)
    }
    token = None
    try:
        token = jwt.encode(payload, SECRET, algorithm='HS256')
        LOGGER.info("Token generated successfully")
    except jwt.exceptions as err:
        LOGGER.error(err)
        raise err
    redirect_url = f"/order?token={token}"
    return redirect(redirect_url)


@app.route("/get_pending_orders", methods=["GET"])
@token_required
@rate_limiter
def get_pending_orders(cid):
    """
    This function returns list of items and their quantity that are pending
    :return: view-orders.html from templates
    """
    LOGGER.info("Pending orders page hit")
    conn, cursor = connect_to_db()
    response = None
    try:
        LOGGER.info("Fetching pending orders...")
        cursor.execute(GET_PENDING_ORDERS_QUERY.format(customer_id=cid))
        response = cursor.fetchall()
        LOGGER.info("Fetched pending orders successfully")
    except psycopg2.OperationalError as err:
        LOGGER.error(err)
        raise err
    except psycopg2.InternalError as err:
        LOGGER.error(err)
        raise err
    except psycopg2.DataError as err:
        LOGGER.error(err)
        raise err
    close_connection(conn, cursor)
    orders = []
    token = request.args['token']
    for item in response:
        orders.append({"item": item[2], "qty": item[3]})
    return render_template("view-orders.html", orders=orders, token=token)


@app.route("/submit_order", methods=["POST"])
@token_required
@rate_limiter
def submit_order(cid):
    """
    This function invokes add_to_db() once the new order gets placed
    :return: Success response
    """
    item = request.form['item']
    qty = request.form['qty']
    conn, cursor = connect_to_db()
    token = request.args['token']
    add_order_to_db(conn, cursor, cid, item, qty)
    close_connection(conn, cursor)
    return render_template("order-submitted.html", token=token)


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=APP_PORT)
