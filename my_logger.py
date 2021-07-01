import logging
import os
import sys
from logging import handlers

# WARNING: do not initialize this as part of an import path!
# It will try to create a directory for consumers during imports, which requires permissions
class My_logger(object):
    """This class initliazes a logger for both file and stream outputs"""

    def __init__(self, logfile, logdir="." "/logs/"):
        self.LOG_DIR = logdir
        if not os.path.isdir(self.LOG_DIR):
            os.makedirs(self.LOG_DIR)

        # LOG_FILE = os.path.join(LOG_DIR, 'ndes_' + datetime.now().strftime('%Y%m%d%H%M%S'))
        self.LOG_FILE = os.path.join(self.LOG_DIR, logfile + ".log")
        self.logger = logging.getLogger("__" + logfile + "__")
        self.logger.setLevel(logging.DEBUG)

        log_formatter = logging.Formatter(
            "%(asctime)s:%(levelname)s:%(name)s:%(message)s"
        )
        file_handler = logging.handlers.TimedRotatingFileHandler(
            self.LOG_FILE, when="midnight", backupCount=7
        )
        file_handler.setFormatter(log_formatter)
        self.logger.addHandler(file_handler)

        self.stream = logging.getLogger("_" + logfile + "_")
        self.stream.setLevel(logging.DEBUG)
        self.stream_formatter = logging.Formatter("%(levelname)s:%(message)s")
        self.stream_handler = logging.StreamHandler(sys.stdout)
        self.stream_handler.setFormatter(self.stream_formatter)
        self.stream.addHandler(self.stream_handler)

    def info(self, message):
        self.logger.info(message)
        # BLACK, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE = range(8)
        # stream_formatter = logging.Formatter('\x1b[1;32m %(levelname)s:%(name)s:%(message)s \x1b[0m')

        self.stream_formatter = logging.Formatter(
            "\x1b[32m[%(levelname)s]\x1b[0m: \x1b[37m%(message)s\x1b[0m"
        )
        self.stream_handler.setFormatter(self.stream_formatter)
        self.stream.info(message)

    def warning(self, message):
        self.logger.warning(message)

        self.stream_formatter = logging.Formatter(
            "\x1b[33m[%(levelname)s]: \x1b[37m%(message)s\x1b[0m"
        )
        self.stream_handler.setFormatter(self.stream_formatter)
        self.stream.warning(message)

    def error(self, message):
        self.logger.error(message)

        self.stream_formatter = logging.Formatter(
            "\x1b[31m[%(levelname)s]: \x1b[37m%(message)s\x1b[0m"
        )
        self.stream_handler.setFormatter(self.stream_formatter)
        self.stream.error(message)

    def title(self, message):
        self.logger.info(message)
        self.stream_formatter = logging.Formatter("\n\x1b[1;37m[%(message)s]\x1b[0m\n")
        self.stream_handler.setFormatter(self.stream_formatter)
        self.stream.info(message)
