#!/usr/bin/env python3
"""Auth Class for user attributes validation
"""

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.exc import InvalidRequestError
from db import DB
from user import User
import bcrypt
import uuid


def _hash_password(password: str) -> str:
    """
    Takes in a password string as an argument and hashes it using a
    salted hash algorithm.
    
    Args:
        password (str): The password string to be hashed.
        
    Returns:
        str: The hashed password as bytes (salted_hashed).
    """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def _generate_uuid() -> str:
    """
    Generates a new UUID (Universally Unique Identifier) and returns
    its string representation.
    
    Returns:
        str: The string representation of the generated UUID.
    """
    return str(uuid.uuid4())


class Auth:
    """
    Auth class provides methods to interact with the authentication database.
    """

    def __init__(self):
        """
        Initializes the Auth class by creating a new instance of the database.
        """
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """
        Registers a new user with the provided email and password.
        
        Args:
            email (str): The email address of the user.
            password (str): The password of the user.
            
        Returns:
            User: A User object representing the newly registered user
            
        Raises:
            ValueError: If a user with the same email already exists in
            the database.
        """
        try:
            self._db.find_user_by(email=email)
            raise ValueError("User {} already exists.".format(email))
        except NoResultFound:
            hashed_password = _hash_password(password)
            new_user = self._db.add_user(email, hashed_password)
            return new_user

    def valid_login(self, email: str, password: str) -> bool:
        """
        Registers a new user with the provided email and password.
        
        Args:
            email (str): The email address of the user.
            password (str): The password of the user.
                
        Returns:
            User: A User object representing the newly registered user.
            
        Raises:
            ValueError: If a user with the same email already exists in
            the database.
        """
        try:
            user = self._db.find_user_by(email=email)
            if bcrypt.checkpw(password.encode('utf-8'), user.hashed_password):
                return True
        except NoResultFound:
            pass
        return False

    def create_session(self, email: str) -> str:
        """
        Creates a new session for the user with the provided email.
        
        Args:
            email (str): The email address of the user.
            
        Returns:
            str: The session ID generated for the user.
        """
        session_id = _generate_uuid()
        try:
            user = self._db.find_user_by(email=email)
            self._db.update_user(user.id, session_id=session_id)
            return session_id
        except NoResultFound:
            return None

    def get_user_from_session_id(self, session_id: str) -> str:
        """
        Retrieves the user corresponding to the provided session ID.
        
        Args:
            session_id (str): The session ID of the user.
            
        Returns:
            str: The email address of the user associated with the session ID.
        """
        try:
            user = self._db.find_user_by(session_id=session_id)
            return user.email
        except NoResultFound:
            return None

    def destroy_session(self, user_id: int) -> None:
        """
        Destroys the session of the user with the provided user ID.
        
        Args:
            user_id (int): The user ID of the user whose session is to
            be destroyed.
        """
        try:
            user = self._db.find_user_by(id=user_id)
            self._db.update_user(user.id, session_id=None)
        except NoResultFound:
            return None

    def get_reset_password_token(self, email: str) -> str:
        """
        Generates a reset password token for the user with the provided email.
        
        Args:
            email (str): The email address of the user.
            
        Returns:
            str: The reset password token generated for the user.
            
        Raises:
            ValueError: If the user with the provided email does not exist
            in the database.
        """
        updated_token = _generate_uuid()
        try:
            user = self._db.find_user_by(email=email)
            self._db.update_user(user.id, reset_token=updated_token)
            return updated_token
        except NoResultFound:
            raise ValueError

    def update_password(self, reset_token: str, password: str) -> str:
        """
        Updates the password of the user corresponding to the provided
        reset token.
        
        Args:
            reset_token (str): The reset password token of the user.
            password (str): The new password to be set for the user.
            
        Returns:
            str: None
            
        Raises:
            ValueError: If the reset token is invalid or if the user
            does not exist in the database.
        """
        if reset_token is None or password is None:
            return None
        try:
            user = self._db.find_user_by(reset_token=reset_token)
        except NoResultFound:
            raise ValueError
        hashed_password = _hash_password(password)
        self._db.update_user(user.id, hashed_password=hashed_password,
                             reset_token=None)
