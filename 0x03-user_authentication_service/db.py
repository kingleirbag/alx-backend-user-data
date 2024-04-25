#!/usr/bin/env python3
"""DB Module
"""

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.exc import InvalidRequestError
from user import Base, User


class DB:
    """
    DB class provides methods to interact with the database.
    """

    def __init__(self):
        """
        Initializes a new DB instance and sets up the database engine.
        """
        self._engine = create_engine("sqlite:///a.db", echo=False)
        Base.metadata.drop_all(self._engine)
        Base.metadata.create_all(self._engine)
        self.__session = None

    @property
    def _session(self):
        """
        Private memoized session method that returns a session object.
        It's used internally within the DB class.
        """
        if self.__session is None:
            DBSession = sessionmaker(bind=self._engine)
            self.__session = DBSession()
        return self.__session

    def add_user(self, email: str, hashed_password: str) -> User:
        """
        Adds a new user to the database.

        Args:
            email (str): The email address of the user.
            hashed_password (str): The hashed password of the user.

        Returns:
            User: A User object representing the newly added user.
        """
        user = User(email=email, hashed_password=hashed_password)
        self._session.add(user)
        self._session.commit()
        return user

    def find_user_by(self, **kwargs) -> User:
        """
        Finds a user in the database based on the provided criteria.

        Args:
            **kwargs: Keyword arguments representing the criteria to
            filter the user.

        Returns:
            User: The first user found in the database that matches
            the specified criteria.

        Raises:
            InvalidRequestError: If an invalid attribute is passed as a filter
            NoResultFound: If no user matches the specified criteria.
        """
        user_keys = ['id', 'email', 'hashed_password', 'session_id',
                     'reset_token']
        for key in kwargs.keys():
            if key not in user_keys:
                raise InvalidRequestError
        result = self._session.query(User).filter_by(**kwargs).first()
        if result is None:
            raise NoResultFound
        return result

    def update_user(self, user_id: int, **kwargs) -> None:
        """
        Updates the attributes of a user in the database.

        Args:
            user_id (int): The ID of the user to update.
            **kwargs: Keyword arguments representing the attributes to update
            and their new values.

        Raises:
            ValueError: If an invalid attribute is passed for updating.
        """
        user_to_update = self.find_user_by(id=user_id)
        user_keys = ['id', 'email', 'hashed_password', 'session_id',
                     'reset_token']
        for key, value in kwargs.items():
            if key in user_keys:
                setattr(user_to_update, key, value)
            else:
                raise ValueError
        self._session.commit()
