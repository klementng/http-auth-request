import os
import logging
import ruamel.yaml

from server.users.object import User


class UserDatabase:

    def __init__(self, path: str) -> None:
        """
        The above function is the constructor for a class that initializes a user database object and loads
        data from a YAML file if it exists, otherwise it creates a new file.
        
        Args:
          path (str): The `path` parameter is a string that represents the file path to a yaml file where the user
        information is stored.
        """
        self.path = path
        self.log = logging.getLogger('UserDatabase')

        self.parser = ruamel.yaml.YAML()
        self.parser.preserve_quotes = True
        self.parser.width = 4096

        self._raw_dict = {}
        self._raw_dict.setdefault('users')
        self.db = self._raw_dict['users']
        self.mtime = 0

        if not os.path.exists(path):
            self.write()

        self.load()

    def load(self):
        """
        The function loads a users database from a file into memory.
        """
        self.log.debug('loading users database into memory')
        with open(self.path) as f:
            self._raw_dict = self.parser.load(f)
            self._raw_dict.setdefault('users', {})
            self.db = self._raw_dict['users']
            self.mtime = os.path.getmtime(self.path)

    def reload(self):
        """
        The `reload` function checks if the modification time of a database file has changed, and if so, it
        reloads the file and update the user database in memory.
        """
        if self.mtime != os.path.getmtime(self.path):
            self.log.debug('change to database file detected. reloading...')

            try:
                self.load()
            except Exception as e:
                self.log.critical(f'Unable to reload. Failed with error: {e}')

    def write(self):
        """
        The function save the database from memory to yaml file.
        """
        self.log.debug('writing database to disk')

        with open(self.path, 'w') as f:
            self.parser.dump(self._raw_dict, f)

    def get_user(self, username: str) -> User | None:
        """
        The function `get_user` retrieves user data from a database based on a given username and returns a
        User object if the data exists, otherwise it returns None.
        
        Args:
          username (str): A string representing the username of the user we want to retrieve.
        
        Returns:
          an instance of the User class or None
        """
        self.reload()

        data = self.db.get(username)

        if data == None:
            return None

        return User(username, data['password'], data['roles'])

    def delete_user(self, username: str):
        """
        The `delete_user` function deletes a user from a database if they exist and logs the action.
        
        Args:
          username (str): The `username` parameter is a string that represents the username of the user you
        want to delete from the database.
        
        Returns:
          a boolean value. It returns True if the user with the given username is successfully deleted from
        the database, and False if the user does not exist in the database.
        """
        
        self.reload()

        if username not in self.db:
            self.log.debug(f"user: {username} does not exist")
            return False

        self.db.pop(username)
        self.write()
        self.log.debug(f"user: {username} removed")
        return True

    def add_user(self, user_obj: User):
        """
        The `add_user` function adds a user object to a database if the user does not already exist.
        
        Args:
          user_obj (User): The parameter `user_obj` is an object of the `User` class.
        
        Returns:
          a boolean value. True if successful. False if the user object's username already exists in the database
        """
        self.reload()

        if user_obj.username in self.db:
            self.log.debug(f"user: {user_obj.username} already exist")
            return False

        self.db.update(user_obj.export())
        self.write()
        self.log.debug(f"user: {user_obj.username} added")
        return True

    def update_user(self, user_obj: User):
        """
        The `update_user` function updates a user object in a database.
        
        Args:
          user_obj (User): The `user_obj` parameter is an instance of the `User` class. It represents the
        user to be updated in the database.
        
        Returns:
          a boolean value. True if successful. False if the user object's username is not in the database
        """

        self.reload()

        if user_obj.username not in self.db:
            self.log.debug(f"user: {user_obj.username} does not exist")
            return False

        self.db.update(user_obj.export())
        self.write()
        self.log.debug(f"user: {user_obj.username} updated")
        return True
