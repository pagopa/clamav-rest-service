from dataclasses import dataclass
from enum import Enum


class ClamdException(Exception):
    """Raised when error occurred communicating with the clamd daemon.
    """


class ClamdScanStatus(Enum):
    """Status of clamd scanning.
    """
    OK = "OK"
    FOUND = "FOUND"
    ERROR = "ERROR"
    # this is not an error returned by clamd, but reflects our
    # inability to parse the clamd response correctly
    CLIENT_PARSE_ERROR = "CLIENT_PARSE_ERROR"


@dataclass
class ClamdCmdResponse():
    """Response of a clamd command.
    """
    raw_data: str
    message: str
    details: list[str]

    def __str__(self):
        return self.raw_data


@dataclass
class ClamdScanResult(ClamdCmdResponse):
    """Result of a clamd scanning.
    """
    input_file: str
    status: ClamdScanStatus
    # TODO file size is not an info clamd returns, it's entirely on
    # the client. therefore, this parameter is probably bad design,
    # but... it's very handy
    # file_size: int
    virus: str | None = None
    err_msg: str | None = None
