"""
the logger module included here is primarily used for local development
it's also useful to ease the creation of file based logger

Unless you want to supply your own formatter, the appropriate default
formatter is used based on the different log level.

Currently, it only means to handle 'debug', 'info', 'warning', 'error'

The file is named as <loggername>_<level>.log, if the loggername ends
with non-alphanumeric characters, it will be sanitized

If no logger name is supplied, it will use the module name as the file
name

Examples
--------
- This create a file myownlogger_info.log, and then log the message
  'whatever' using the default formatter
  ```
    >> import logger
    >> info_logger = logger.get_info_logger('myownlogger')
    >> info_logger.info('whatever')
  ```
- This create a file logger logger_debug.log, and then log the message
  'example' using the default formatter
  ```
    >> import logger
    >> debug_logger = logger.get_debug_logger()
    >> debug_logger.debug('example')
  ```

"""
from typing import Callable, TypeVar, Union
import logging
import string

try:
    from typing import Literal  # only available in python 3.8 and above
except ImportError:
    from typing_extensions import Literal

TLogHandler = TypeVar('TLogHandler', bound=logging.Handler)
TLogger = TypeVar('TLogger', bound=logging.Logger)
TLogLevel = Literal[logging.CRITICAL, logging.ERROR, logging.WARNING,
                  logging.INFO, logging.DEBUG]
TLogFormatter = TypeVar('TLogFormatter', bound=logging.Formatter)

def _setup_logger(logger:TLogger,
                 handler:TLogHandler,
                 formatter:TLogFormatter,
                 log_level:TLogLevel) -> None:
    """
    setup the logger with the handler, log level and formatter
    """
    logger.setLevel(log_level)
    handler.setLevel(log_level)
    handler.setFormatter(formatter)
    logger.addHandler(handler)

_alpha_numerics = string.ascii_letters + string.digits

def sanitize_file_name(name:str) -> str:
    """
    return name that ends with alpha numerics, characters not
    ending in alpha numerics are removed
    """
    last_pos = len(name) - 1
    while name[last_pos] not in _alpha_numerics:
        if last_pos == 0:
            raise ValueError(f'{name} is not valid!')
        last_pos -= 1
    return name[:last_pos + 1]

_log_level_mapping = {'debug': logging.DEBUG,
                     'info': logging.INFO,
                     'warning': logging.WARNING,
                     'error': logging.ERROR}

DEFAULT_DEBUG_LOG_FORMATTER = \
    logging.Formatter('%(asctime)s | %(levelname)s | %(filename)s: %(lineno)d | %(message)s')
DEFAULT_INFO_LOG_FORMATTER = \
    logging.Formatter('%(asctime)s | %(levelname)s | %(message)s')
DEFAULT_WARNING_LOG_FORMATTER = \
    logging.Formatter('%(asctime)s | WARNING | %(message)s')
DEFAULT_ERROR_LOG_FORMATTER = \
    logging.Formatter('%(asctime)s | ERROR | %(message)s')

FILE_HANDLERS = {}
def level_logger_factory(
        log_level:Literal['debug', 'info', 'warning', 'error'] = 'info',
        log_formatter:TLogFormatter = DEFAULT_INFO_LOG_FORMATTER
    ) -> Callable[[str, TLogFormatter], TLogger]:
    """
    a file based logger factory for the appropriate log level
    """
    def _get_logger(logger_name:str = __name__,
                    log_formatter:TLogFormatter = log_formatter
                    ) -> TLogger:
        """
        return the appropriate logger
        """

        log_file_name = f'{sanitize_file_name(logger_name)}_{log_level}.log'

        log_handler = FILE_HANDLERS.get(log_file_name)
        use_new_handler = False
        if log_handler is None:
            log_handler = logging.FileHandler(log_file_name)
            FILE_HANDLERS[log_file_name] = log_handler
            use_new_handler = True

        logger = logging.getLogger(logger_name)
        if use_new_handler:
            _setup_logger(logger, log_handler, log_formatter,
                         _log_level_mapping[log_level])
        return logger

    return _get_logger

get_info_logger = level_logger_factory()
get_debug_logger = level_logger_factory('debug', DEFAULT_DEBUG_LOG_FORMATTER)
get_warning_logger = level_logger_factory('warning', DEFAULT_WARNING_LOG_FORMATTER)
get_error_logger = level_logger_factory('error', DEFAULT_ERROR_LOG_FORMATTER)
