#!/usr/bin/env python3
"""Route module for basic API for flask app
"""

from db import DB
from flask import Flask, jsonify, request, abort, redirect
from flask.helpers import make_response
from auth import Auth
from user import User

AUTH = Auth()

app = Flask(__name__)


@app.route('/', methods=['GET'], strict_slashes=False)
def welcome() -> str:
    """
    GET /

    Handles a GET request to the root endpoint. Returns a
    welcome message in French.

    Returns:
        str: A JSON response containing a welcome message in French.
    """
    return jsonify({"message": "Bienvenue"})


@app.route('/users', methods=['POST'], strict_slashes=False)
def users() -> str:
    """
    POST /users, JSON: -email, -password

    Handles a POST request to the '/users' endpoint. It expects JSON data with
    'email' and 'password' fields. Attempts to register a new user with the
    provided email and password. If successful, returns a JSON response with
    the email of the created user and a success message. If the email is
    already registered, returns a JSON response with an error message and a
    status code of 400.

    Returns:
        str: A JSON response containing either a success message with the
        email of the created user or an error message if the email is
        already registered.

    Raises:
        400 Bad Request: If the email is already registered.
    """
    email = request.form.get('email')
    password = request.form.get('password')
    try:
        AUTH.register_user(email, password)
        return jsonify({"email": email, "message": "user created"})
    except Exception:
        return jsonify({"message": "email already registered"}), 400


@app.route('/sessions', methods=['POST'], strict_slashes=False)
def login():
    """
    POST /sessions, - email, - password

    Authenticates user credentials by accepting a POST request with 'email'
    and 'password' parameters. If the credentials are valid, it creates a
    session for the user and returns a response with a cookie containing
    the session ID.

    Returns:
        response (Flask Response): A Flask Response object containing JSON
        data with the user's email and a success message

    Raises:
        401 Unauthorized: If the provided credentials are invalid.
    """
    user_request = request.form
    user_email = user_request.get('email', '')
    user_password = user_request.get('password', '')
    valid_log = AUTH.valid_login(user_email, user_password)
    if not valid_log:
        abort(401)
    response = make_response(jsonify({"email": user_email,
                                      "message": "logged in"}))
    response.set_cookie('session_id', AUTH.create_session(user_email))
    return response


@app.route('/sessions', methods=['DELETE'], strict_slashes=False)
def logout():
    """
    DELETE /sessions, - session_id

    Handles a DELETE request to the '/sessions' endpoint. It expects a
    'session_id' cookie in the request. Finds the user associated with
    the provided session ID. If the session exists, it destroys the session.
    Redirects the user to the root endpoint ('/'). If the session does not
    exist or if the 'session_id' cookie is missing, it responds with a 403
    Forbidden HTTP status.

    Returns:
        Redirect: Redirects the user to the root endpoint ('/').

    Raises:
        403 Forbidden: If the session ID is missing or if no user is
        associated with the session ID.
    """
    user_cookie = request.cookies.get("session_id", None)
    user = AUTH.get_user_from_session_id(user_cookie)
    if user_cookie is None or user is None:
        abort(403)
    AUTH.destroy_session(user.id)
    return redirect('/')


@app.route('/profile', methods=['GET'], strict_slashes=False)
def profile() -> str:
    """
    GET /profile

    Handles a GET request to the '/profile' endpoint. It retrieves the session
    ID from the cookie. Uses the session ID to find the corresponding user.
    If the session ID is missing or invalid, it responds with a 403 Forbidden
    HTTP status. Otherwise, it returns a JSON response containing the user's
    email address.

    Returns:
        str: A JSON response containing the user's email address.

    Raises:
        403 Forbidden: If the session ID is missing or invalid.
    """
    user_cookie = request.cookies.get("session_id", None)
    user = AUTH.get_user_from_session_id(user_cookie)
    if user_cookie is None or user is None:
        abort(403)
    return jsonify({"email": user}), 200


@app.route('/reset_password', methods=['POST'], strict_slashes=False)
def get_reset_password_token_route() -> str:
    """
    POST /reset_password, - email

    Handles a POST request to the '/reset_password' endpoint. It expects a
    JSON payload with the 'email' field. Checks if the provided email is
    registered. If the email is not registered, it responds with a 403
    Forbidden HTTP status code. If the email is registered, it generates a
    reset password token and responds with a JSON object containing the email
    and the reset token with a status code of 200 OK.

    Returns:
        str: A JSON response containing the email and reset token.

    Raises:
        403 Forbidden: If the provided email is not registered.
    """
    user_request = request.form
    user_email = user_request.get('email', '')
    is_registered = AUTH.create_session(user_email)
    if not is_registered:
        abort(403)
    token = AUTH.get_reset_password_token(user_email)
    return jsonify({"email": user_email, "reset_token": token})


@app.route('/reset_password', methods=['PUT'], strict_slashes=False)
def update_password() -> str:
    """
    PUT /reset_password, - email, - reset_token, - new_password

    Handles a PUT request to the '/reset_password' endpoint. It expects a
    JSON payload with 'email', 'reset_token', and 'new_password' fields.
    Checks if the provided reset token is valid. If the token is invalid, it
    responds with a 403 Forbidden HTTP status code. If the token is valid, it
    updates the user's password with the new password and responds with a JSON
    object containing the user's email and a success message with a status
    code of 200 OK.

    Returns:
        str: A JSON response containing the user's email and a success message.

    Raises:
        403 Forbidden: If the reset token is invalid.
    """
    user_email = request.form.get('email')
    reset_token = request.form.get('reset_token')
    new_password = request.form.get('new_password')
    try:
        AUTH.update_password(reset_token, new_password)
    except Exception:
        abort(403)
    return jsonify({"email": user_email, "message": "Password updated"}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
