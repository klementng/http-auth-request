"""Config file with all environmental variables and its default values """

import os
import logging
import secrets

CONFIG_DIR = os.getenv("CONFIG_DIR", "/config")
CONFIG_PATH = os.getenv("CONFIG_PATH", os.path.join(CONFIG_DIR, 'config.yml'))

#CACHE_TTL = os.getenv("CACHE_TTL", '60')
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

logging.basicConfig(
    format='%(asctime)s - %(name)s - %(funcName)s() - %(levelname)s - %(message)s', 
    level=LOG_LEVEL
)

os.environ["FLASK_SESSION_COOKIE_DOMAIN"] = os.getenv("FLASK_SESSION_COOKIE_DOMAIN", "")
os.environ["FLASK_SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY", secrets.token_hex(16))
os.environ["FLASK_SESSION_TYPE"] = os.getenv("FLASK_SESSION_TYPE", 'filesystem')
os.environ["FLASK_SESSION_PERMANENT"] = os.getenv("FLASK_SESSION_PERMANENT", 'False')
os.environ["FLASK_PERMANENT_SESSION_LIFETIME"] = os.getenv("PERMANENT_SESSION_LIFETIME", '1209600') # Valid for 14 days