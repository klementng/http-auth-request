import logging 
import ruamel.yaml


from server.authentication import AuthenticationModule

from server.shared.exception import ConfigurationError

logger = logging.getLogger(__name__)

def parse_config(path:str):
    try:
        logger.debug("Parsing YAML config file")

        yaml_f = open(path)
        config = ruamel.yaml.safe_load(yaml_f)
        yaml_f.close()

        settings = config["settings"]
        modules = config["modules"]

        for key in modules.keys():
            modules[key] = AuthenticationModule.from_dict(modules[key]) # type: ignore

        return settings, modules

    except Exception as e:
        logger.fatal(f"Aborting. Invalid Configuration: {e} ")
        raise ConfigurationError(e)