from starlette.types import Receive, Scope, Send
from starlette.requests import HTTPConnection
from base64 import b64decode
import itsdangerous
from itsdangerous.exc import BadTimeSignature, SignatureExpired
import binascii
import json
import logging
from typing import List

MAX_AGE: int = 31 * 24 * 60 * 60  # a month in seconds


def process(config, scope: Scope, receive: Receive, send: Send) -> List:
    cookie_data = {}
    http_connection = HTTPConnection(scope)

    for cookie_config in config:
        if cookie_config in http_connection.cookies:
            _cookie_data = http_connection.cookies[cookie_config].encode('utf-8')
            _cookie_enc_key = config[cookie_config]['secret']
            _cookie_signer = itsdangerous.TimestampSigner(str(_cookie_enc_key))
            _cookie_max_age = MAX_AGE \
                if config[cookie_config].get('max_age', None) is None \
                else config[cookie_config]['max_age']
            try:
                _cookie_data = _cookie_signer.unsign(_cookie_data, _cookie_max_age)
                _cookie_data = json.loads(b64decode(_cookie_data))
            except (BadTimeSignature, BadTimeSignature, SignatureExpired, binascii.Error) as e:
                _cookie_data = {}
            except Exception as e:
                _cookie_data = {}
                logging.error(str(e))
            cookie_data.update({cookie_config: _cookie_data})
    return cookie_data
