"""
Log generation constructs.

The logs generated by these wrappers are seperated into three seperate files
each with a maximum size of 2 GB. This is to enable the ability to pull logs
from the machine collecting data without interrupting the collection process.

"""

# Debugging and recording
import logging
from logging.handlers import RotatingFileHandler

# Set max logging file size to 2GB
MAX_LOG_FILE_SIZE       =   (2 * (1024**3))

# Logging instances, formatters, and file handlers
clog                    =   logging.getLogger("cert_only")
cert_formatter          =   logging.Formatter("%(message)s")
cert_rot_file_handler   =   RotatingFileHandler(
                                        "logs/certificates.log",
                                        mode            =   'a',
                                        maxBytes        =   MAX_LOG_FILE_SIZE,
                                        backupCount     =   3,
                                        encoding        =   None,
                                        delay           =   0
                            )

# Logging instances, formatters, and file handlers
log                     =   logging.getLogger("base")
base_formatter          =   logging.Formatter(
                                    "%(asctime)s [%(levelname)s]: %(message)s",
                                    "%Y-%m-%d %H:%M:%S"
                            )

base_rot_file_handler   =   RotatingFileHandler(
                                        "logs/output.log",
                                        mode            =   'a',
                                        maxBytes        =   MAX_LOG_FILE_SIZE,
                                        backupCount     =   3,
                                        encoding        =   None,
                                        delay           =   0
                            )


# Set logging level
clog.setLevel(logging.DEBUG)
log.setLevel(logging.DEBUG)

# Create file handlers and set the logging level of the file handler
cert_rot_file_handler.setLevel(logging.DEBUG)
cert_rot_file_handler.setFormatter(cert_formatter)
base_rot_file_handler.setLevel(logging.DEBUG)
base_rot_file_handler.setFormatter(base_formatter)

# Add the file handlers to the logger
clog.addHandler(cert_rot_file_handler)
log.addHandler(base_rot_file_handler)