#!/usr/bin/env python3
"""
Session Authentication
"""
from typing import Dict
from flask.globals import session
from api.v1.auth.auth import Auth
from models.user import User
import uuid


class SessionAuth(Auth):
    """- Methods for session
    - inherits from Auth
    Args:
        Auth (class): Parent authentication class
    """
    user_id_by_session_id: Dict[str, str] = {}

    def create_session(self, user_id: str = None) -> str:
        """Session ID Generator
        Returns session id
        Args:
            self (_type_): Basic auth instance
            user_id(str): user id
        """
        if user_id is None or not isinstance(user_id, str):
            return None
        session_id = str(uuid.uuid4())
        self.user_id_by_session_id[session_id] = user_id
        return session_id

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """Get session ID Generator for a user
        Returns session id based on user id 
        Args:
            self (_type_): Basic auth instance
            session_id(str): session id
        """
        if session_id is None or not isinstance(session_id, str):
            return None
        return self.user_id_by_session_id.get(session_id, None)

    def current_user(self, request=None):
        """Retrieve User based cookie value
        Returns User based cookie value
        Args:
            self (_type_): Basic auth instance
        """
        cookie = self.session_cookie(request)
        session_user_id = self.user_id_for_session_id(cookie)
        user_id = User.get(session_user_id)
        return user_id

    def destroy_session(self, request=None):
        """Deletes user session / login(out)
        Args:
            self (_type_): Basic auth instance
        """
        cookie_data = self.session_cookie(request)
        if cookie_data is None:
            return False
        if not self.user_id_for_session_id(cookie_data):
            return False
        del self.user_id_by_session_id[cookie_data]
        return True
