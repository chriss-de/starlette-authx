from starlette.requests import Request
from starlette.types import Receive, Scope, Send
from base64 import b64decode
import binascii
from passlib.apache import HtpasswdFile
from . import InvalidToken
import logging


def check_against_htpasswd(htpasswd_file, username, password):
    try:
        htpasswd = HtpasswdFile(htpasswd_file)
        return htpasswd.check_password(username, password)
    except (FileNotFoundError, Exception) as e:
        logging.warning(f"file '{htpasswd_file}' not found")
        return False


def process(config, scope: Scope, receive: Receive, send: Send) -> dict:
    client_basic_auth_results = {'groups': []}
    request = Request(scope)

    if 'authorization' in request.headers and request.headers['authorization'].startswith('Basic '):
        token = request.headers['authorization'][len('Basic '):]

        # 'decrypt' base64 token_data
        try:
            data = b64decode(token).decode("ascii")
        except(ValueError, UnicodeDecodeError, binascii.Error, Exception) as e:
            raise InvalidToken(str(e))

        # split username and password
        username, separator, password = data.partition(":")
        if not separator:
            raise InvalidToken("missing basic separator")

        # check against all configured htpasswd files
        for basic_auth_group in config:
            for htpasswd_file in config[basic_auth_group]:
                if check_against_htpasswd(htpasswd_file, username, password):
                    client_basic_auth_results['username'] = username
                    client_basic_auth_results['groups'].append(basic_auth_group)

    return client_basic_auth_results
