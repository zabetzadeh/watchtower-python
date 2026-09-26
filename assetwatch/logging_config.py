import logging
from logging.handlers import RotatingFileHandler


class SecretFilter(logging.Filter):
    def __init__(self, secrets):
        super().__init__()
        self.secrets = [value for value in secrets if value]

    def filter(self, record):
        message = record.getMessage()
        for secret in self.secrets:
            message = message.replace(secret, "[REDACTED]")
        record.msg, record.args = message, ()
        return True


def configure_logging(config):
    import os

    settings = config["logging"]
    path = config.path(settings["file"])
    path.parent.mkdir(parents=True, exist_ok=True)
    handlers = [logging.StreamHandler(), RotatingFileHandler(
        path, maxBytes=settings["max_bytes"], backupCount=settings["backup_count"], encoding="utf-8")]
    formatter = logging.Formatter("%(asctime)s %(levelname)-7s %(name)s %(message)s")
    secrets = [config["telegram"]["bot_token"], config["chaos"]["api_key"],
               os.environ.get("PDCP_API_KEY"), os.environ.get("CHAOS_KEY")]
    for handler in handlers:
        handler.setFormatter(formatter)
        handler.addFilter(SecretFilter(secrets))
    logging.basicConfig(level=settings["level"], handlers=handlers, force=True)
