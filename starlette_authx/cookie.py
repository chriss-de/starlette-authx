from starlette.types import Receive, Scope, Send
from starlette.requests import HTTPConnection
from base64 import b64decode
import itsdangerous
from itsdangerous.exc import BadTimeSignature, SignatureExpired
import binascii
import json
from typing import List

MAX_AGE: int = 31 * 24 * 60 * 60  # a month in seconds


def process(config, scope: Scope, receive: Receive, send: Send) -> List:
    http_connection = HTTPConnection(scope)

    for cookie_config in config:
        if cookie_config in http_connection.cookies:
            cookie_data = http_connection.cookies[cookie_config].encode('utf-8')
            cookie_enc_key = config[cookie_config]['secret']
            cookie_signer = itsdangerous.TimestampSigner(str(cookie_enc_key))
            cookie_max_age = MAX_AGE \
                if config[cookie_config].get('max_age', None) is None \
                else config[cookie_config]['max_age']
            try:
                cookie_data = cookie_signer.unsign(cookie_data, cookie_max_age)
                cookie_data = json.loads(b64decode(cookie_data))
            except (BadTimeSignature, SignatureExpired, binascii.Error) as e:
                cookie_data = {}

            return cookie_data
