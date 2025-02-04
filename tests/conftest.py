# WARNING this tests require running clamd daemon

import pytest
from clamav_rest_service import app


@pytest.fixture()
def test_app():
    app.config.update({
        "TESTING": True,
        "CLAMD_SOCKET_PATH": "/tmp/clamd.sock",
    })

    yield app

    # clean up / reset resources here


@pytest.fixture()
def client(test_app):
    return test_app.test_client()
