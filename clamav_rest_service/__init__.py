"""ClamAV REST Service is a REST interface for ClamAV daemon.

The ClamAV daemon (clamd) can be either reached via Unix domain socket
or TCP socket.  This behaviour can be specified via configuration.

Configuration: all configuration is managed through environment
variables.  All environment variables starting with "CLAMAV_" prefix
are loaded into the application.

No authentication of any type is implemented whatsoever: be sure that
your ClamAV REST service is adequately protected.

The following variables are accepted:

 - CLAMAV_CLAMD_SOCKET_PATH : application will connect to clamd
    running on Unix socket at path specified.
 - CLAMAV_CLAMD_HOST : application will connect to clamd running on TCP
    socket at host specified; also CLAMAV_CLAMD_PORT is expected
 - CLAMAV_CLAMD_PORT : use with CLAMAV_CLAMD_PORT

"""
import logging

from flask import Flask, jsonify, render_template, request
from flask.logging import default_handler
from flask_swagger import swagger
from werkzeug.exceptions import HTTPException

from .clamd import ClamdUnixSocket, ClamdTCPSocket, ClamdScanStatus

##
# Init app and config
##

app = Flask(__name__)

# load all env starting with CLAMAV_ and make them available in
# app.config without CLAMAV_
app.config.from_prefixed_env("CLAMAV")

# fix gunicorn logging
if __name__ != '__main__':
    gunicorn_logger = logging.getLogger('gunicorn.error')
    app.logger.handlers = gunicorn_logger.handlers[:]
    app.logger.setLevel(gunicorn_logger.level)
    app.logger.propagate = False

##
# Pages
##


@app.route("/", methods=["GET"])
@app.route("/index.html", methods=["GET"])
def index():
    """Welcome page.
    """
    # try to ping clamd
    try:
        with clamd_instance() as clamd:
            pong = clamd.ping().message
        connection_up = pong == "PONG"
    except Exception as e:
        app.logger.exception("Unable to ping clamav: %s", str(e))
        connection_up = False

    if connection_up:
        # try to get clamd version
        try:
            with clamd_instance() as clamd:
                version = clamd.version().message
        except Exception as e:
            app.logger.exception("Unable to get clamav stats: %s", str(e))
            stats = "Unable to get ClamAV version."

        # try to get clamd stats
        try:
            with clamd_instance() as clamd:
                stats = clamd.stats().message
        except Exception as e:
            app.logger.exception("Unable to get clamav stats: %s", str(e))
            stats = "Unable to get ClamAV stats."
    else:
        pong = version = stats = "Unable to connect to ClamAV service."

    return render_template(
        "index.html",
        connection_up=connection_up,
        pong=pong,
        version=version,
        stats=stats,
    )


@app.route("/swagger-ui")
def swagger_ui():
    """Swagger UI page.
    """
    return render_template("swagger-ui.html")


##
# API
##


@app.route("/api/v1/doc")
def api_doc():
    """OpenAPI spec of the v1 API.
    """
    swag = swagger(app)
    swag['info']['version'] = "1.0"
    swag['info']['title'] = "ClamAV REST service"
    swag['info']['description'] = \
        "Sandboxed file scanning with ClamAV via REST API"
    return jsonify(swag)


@app.route("/health", methods=["GET"])
@app.route("/api/v1/clamav/ping", methods=["GET"])
def ping():
    """Ping clamav ensuring connection is up.
    ---
    tags:
      - status
    responses:
      200:
        description: Pong
        content: application/json
        schema:
          type: object
          properties:
            status:
              type: string
              description: Status of the ping
              example: OK
            message:
              type: string
              description: Message returned by clamav on ping command
              example: PONG
            error:
              type: string
              description: Error occurred, if any
    """
    app.logger.debug("Pinging clamd...")
    with clamd_instance() as clamd:
        pong = clamd.ping()
    app.logger.debug("Ping clamd raw response: %s", pong.raw_data)

    if pong.message == "PONG":
        status = "OK"
        code = 200
    else:
        status = "KO"
        code = 503

    return {
        "status": status,
        "message": pong.message,
    }, code


@app.route("/api/v1/clamav/scan", methods=["POST"])
def scan_file():
    """Scan a file attached to the request.
    ---
    tags:
      - scan
    parameters:
      - in: formData
        name: file
        description: File to scan
        required: true
    responses:
      200:
        description: Scanning result
        content: application/json
        schema:
          type: object
          properties:
            status:
              type: string
              description: Status of the scanning {OK,FOUND,ERROR}
              example: FOUND
            input_file:
              type: string
              description: Input file that was scanned
              example: myfile.txt
            virus:
              type: string
              description: Virus found, if any
              example: Name-Of-Virus-Found
            error:
              type: string
              description: Error occurred, if any
            file_size:
              type: integer
              description: Size of the file scanned in bytes
              example: 256
            details:
              type: array
              description: Additional lines of details, if any
    """
    if 'file' not in request.files:
        return {"error": "No file attached"}, 400
    file_to_analyze = request.files['file']
    filename = file_to_analyze.filename
    # sanitize filename to prevent log injection
    safe_filename = filename.replace('\r\n', '').replace('\n', '')

    app.logger.debug("Starting scan for file \"%s\"", safe_filename)
    with clamd_instance() as clamd:
        # we send an open stream to the clamd instance
        result = clamd.instream(file_to_analyze.stream)

    # the file pointer is at the end of the stream, so tell() will
    # give us the size in bytes
    file_size = file_to_analyze.stream.tell()
    app.logger.info("Scanned file \"%s\" (%d bytes) with status %s - %s",
                    safe_filename, file_size, result.status.value, result.virus
                    or "no virus")
    app.logger.debug("Scan raw response: %s", result.raw_data)

    # pack the response
    resp_body = {
        "status": result.status.value,
        # the input_file is always "stream" as returned by clamd
        # INSTREAM command, use what the client told us about the file
        # for a more significative response to the user "input_file":
        "input_file": filename,
        "virus": result.virus,
        "details": result.details,
        "error": result.err_msg,
        "file_size": file_size,
    }
    if config_bool("INCLUDE_RAW_DATA"):
        app.logger.warning("Including raw data in scan response. "
                           "Use this option only for debugging")
        resp_body["raw_data"] = result.raw_data

    # decide http status code
    if result.status == ClamdScanStatus.ERROR:
        status_code = 500
        app.logger.error("Detected clamd error: %s", result.err_msg)
    if result.status == ClamdScanStatus.CLIENT_PARSE_ERROR:
        # this is not a clamd error, but our error in parsing response
        status_code = 500
        app.logger.error("Unable to parse clamd response. Raw response: %s",
                         result.raw_data)
    else:
        status_code = 200

    return resp_body, status_code


@app.route("/api/v1/clamav/stats", methods=["GET"])
def stats():
    """Get clamav stats.
    ---
    tags:
      - status
    responses:
      200:
        description: ClamAV stats
        content: application/json
        schema:
          type: object
          properties:
            message:
              type: string
              description: ClamAV stats message
            details:
              type: array
              description: Additional lines of details, if any
            error:
              type: string
              description: Error occurred, if any
    """
    app.logger.debug("Requesting clamd stats...")
    with clamd_instance() as clamd:
        stats = clamd.stats()
    app.logger.debug("Stats clamd raw response: %s", stats.raw_data)

    return {
        "message": stats.message,
        "details": stats.details,
    }


@app.route("/api/v1/clamav/version", methods=["GET"])
def clamav_version():
    """Get version of connected clamav instance.
    ---
    tags:
      - status
    responses:
      200:
        description: ClamAV version
        content: application/json
        schema:
          type: object
          properties:
            message:
              type: string
              description: ClamAV version message
              example: ClamAV 1.4.2
            details:
              type: array
              description: Additional lines of details, if any
            error:
              type: string
              description: Error occurred, if any
    """
    with clamd_instance() as clamd:
        version = clamd.version()

    return {
        "message": version.message,
        "details": version.details,
    }


##
# Error handlers
##


@app.errorhandler(HTTPException)
def handle_http_exception(e):
    """Handle an HTTP exception and return JSON.
    """
    str_e = str(e)
    if e.code not in [404, 405, 415]:
        # don't pollute logs, these statuses does not concern us
        app.logger.exception("HTTP exception: %s", str_e)
    return {"error": str_e}, e.code


@app.errorhandler(Exception)
def handle_exception(e):
    """Handle an generic exception and return JSON.
    """
    str_e = str(e)
    app.logger.exception("Generic exception: %s", str_e)
    return {"error": str_e}, 500


##
# Helpers
##


def clamd_instance():
    """Get a clamd isntance based on app config.
    """
    # remember, these are env variables prefixed with CLAMAV_
    host = app.config.get("CLAMD_HOST")
    port = app.config.get("CLAMD_PORT")

    if host is not None and port is not None:
        return ClamdTCPSocket(host=host, port=port)

    socket_path = app.config.get("CLAMD_SOCKET_PATH") or "/tmp/clamd.sock"
    return ClamdUnixSocket(socket_path)


def config_bool(env_name: str) -> bool:
    """Given a config var name, try to parse as boolean.
    """
    val = app.config.get(env_name, "false").strip().lower()
    return val in ["true", "1", "enable", "enabled"]


##
# DEV runner
##

if __name__ == "__main__":
    # don't run directly in prod, use a production grade wsgi server
    # like gunicorn
    app.run(host="0.0.0.0", port=8080, debug=True)
