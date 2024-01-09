class UserObjectError(Exception):
    pass

class UserCreateError(UserObjectError):
    pass

class UserHashingError(UserObjectError):
    pass