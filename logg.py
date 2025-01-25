import logging
import os
import time
from functools import partial

class CustomFormatter(logging.Formatter):
    LEVEL_COLORS = {
        "INFO": "\033[38;5;120mINF\033[0m \033[38;5;239m>\033[0m",
        "DEBUG": "\033[38;5;221mDBG\033[0m \033[38;5;239m>\033[0m",
        "WARNING": "\033[38;5;203mWRN\033[0m \033[38;5;239m>\033[0m",
        "ERROR": "\033[1m\033[38;5;203mWRN\033[0m\033[0m \033[38;5;239m>\033[0m",
        "CRITICAL": "\033[1m\033[38;5;209mFTL\033[0m\033[0m \033[38;5;239m>\033[0m",
    }

    def __init__(self):
        super().__init__()
        self.default_time_format = "%I:%M %p"

    def format(self, record):
        level_color = self.LEVEL_COLORS.get(record.levelname, record.levelname)
        record.levelname = level_color
        record.time = time.strftime(self.default_time_format, time.localtime(record.created))

        record.message = record.getMessage()
        log_msg = (
            f"{record.time} {record.levelname} {record.message}"
        )

        if record.exc_info:
            log_msg += "\n" + self.formatException(record.exc_info)

        return log_msg

class InputFormatter:
    def __init__(self):
        self.prompt_color = "\033[38;5;120m>>\033[0m "

    def format_input(self, prompt):
        return f"{self.prompt_color}{prompt}"

class CustomLogger:
    def __init__(self):
        self.logger = logging.getLogger("custom_logger")
        self.logger.setLevel(logging.DEBUG)

        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.DEBUG)
        console_handler.setFormatter(CustomFormatter())

        self.logger.addHandler(console_handler)
        self.input_formatter = InputFormatter()

    def info(self, msg, *args, **kwargs):
        self.logger.info(msg, *args, **kwargs)

    def debug(self, msg, *args, **kwargs):
        self.logger.debug(msg, *args, **kwargs)

    def warning(self, msg, *args, **kwargs):
        self.logger.warning(msg, *args, **kwargs)

    def error(self, msg, *args, **kwargs):
        self.logger.error(msg, *args, **kwargs)

    def critical(self, msg, *args, **kwargs):
        self.logger.critical(msg, *args, **kwargs)

    def input(self, prompt):
        formatted_prompt = self.input_formatter.format_input(prompt)
        return input(formatted_prompt)

