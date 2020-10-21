from starlette.types import Receive, Scope, Send
from starlette.requests import HTTPConnection, Request
from starlette.responses import RedirectResponse
from base64 import b64decode, b64encode
from requests_oauthlib import OAuth2Session
import itsdangerous
from itsdangerous.exc import BadSignature
import json
from . import merge_auth_info
from .utils import validator

MAX_AGE: int = 31 * 24 * 60 * 60  # a month in seconds


def validate_config(config):
    mandatory_keys = {'uri', 'client_id', 'idp', 'redirect_uri'}

    for _cookie_config, _cookie_config_data in config.items():
        if not mandatory_keys.issubset(set(_cookie_config_data)):
            raise ValueError(
                f'Each entry must contain the following keys: {mandatory_keys}.'
                f' Config "{_cookie_config}" is missing {mandatory_keys - set(_cookie_config_data)}.'
            )


def _get_cookie_configs(config):
    _cookie_configs = {}
    for k, v in config.items():
        _paths = []
        uri = v.get('uri')
        if isinstance(uri, list):
            _paths.extend(uri)
        if isinstance(uri, str):
            _paths.append(uri)
        _cookie_configs[k] = {'uris': tuple(_paths), 'config': v}
    return _cookie_configs


def _get_signer(config):
    _cookie_key = __name__
    if 'secret' in config:
        _cookie_key = config['secret']
    return itsdangerous.TimestampSigner(str(_cookie_key))


def _get_max_age(config):
    cookie_max_age = MAX_AGE
    if config.get('max_age', None) is not None:
        _cookie_max_age = config['max_age']
    return cookie_max_age


def _get_cookie_data(oauth2_cookie_config, cookie_data):
    _cookie_signer = _get_signer(oauth2_cookie_config)
    _cookie_max_age = _get_max_age(oauth2_cookie_config)
    try:
        _cookie_data = cookie_data.encode('utf-8')
        _cookie_data = _cookie_signer.unsign(cookie_data, _cookie_max_age)
        _cookie_data = json.loads(b64decode(_cookie_data))
    except (BadSignature, Exception) as e:
        _cookie_data = {}
    return _cookie_data


def _create_state_cookie_data(config, state, req_uri):
    _cookie_content = {'state': state, 'type': 'state', 'request_uri': req_uri}
    data = b64encode(json.dumps(_cookie_content).encode('utf-8'))
    data = _get_signer(config).sign(data)
    return data.decode('utf-8')


def _create_oauth2_redirect_response(scope, receive, name, config):
    _request = Request(scope, receive)
    _redirect_uri = config.get('redirect_uri')
    _client = OAuth2Session(
        client_id=config['client_id'],
        redirect_uri=_redirect_uri
    )
    _auth_url, state = _client.authorization_url(f"{config['idp']}/authorize")
    response = RedirectResponse(_auth_url, status_code=307)
    response.set_cookie(
        key=name, value=_create_state_cookie_data(config, state, str(_request.url)),
        secure=True, samesite='none', httponly=True, expires='session',  # path=oauth2_cookie_path
    )
    return response


def _create_token_cookie_data(config, token):
    _cookie_content = {'type': 'token', 'token': token}
    data = b64encode(json.dumps(_cookie_content).encode('utf-8'))
    data = _get_signer(config).sign(data)
    return data.decode('utf-8')


def _fetch_grant_token(config, state, code):
    _client = OAuth2Session(client_id=config['client_id'], state=state, redirect_uri=config.get('redirect_uri'))
    _token = _client.fetch_token(token_url=f"{config['idp']}/token", code=code, )
    return _token


async def process(config, scope: Scope, receive: Receive, send: Send) -> None:
    cookie_data = {}
    _oauth_cookie_configs = _get_cookie_configs(config)
    for oauth2_cookie_name, oauth2_cookie_config in _oauth_cookie_configs.items():
        _uri_index = [
            oauth2_cookie_config['uris'].index(i) for i in oauth2_cookie_config['uris'] if scope['path'].startswith(i)
        ]
        if len(_uri_index) > 0:
            oauth2_cookie_config = oauth2_cookie_config['config']
            if 'only_if_not' in oauth2_cookie_config:
                _condition = oauth2_cookie_config['only_if_not']
                _res = validator(f"not ({_condition})", config=scope.get('authx', {}))
                if _res:
                    continue

            oauth2_cookie_path = oauth2_cookie_config['uris'][_uri_index[0]]
            http_connection = HTTPConnection(scope)

            # do we have a cookie?
            if oauth2_cookie_name in http_connection.cookies:
                _cookie_data = _get_cookie_data(oauth2_cookie_config, http_connection.cookies[oauth2_cookie_name])

                _cookie_type = _cookie_data.get('type')
                if _cookie_type is not None:
                    if _cookie_type == 'state':
                        # read state from cookie and code from URI and fetch access_token
                        # this breaks if multiple req were made and the state is wrong
                        # TODO: safe state not in cookie OR all states in cookie
                        # TODO: where to safe state - needs shared data if running in K8S with scaled deployment
                        response = RedirectResponse(_cookie_data['request_uri'], status_code=302)
                        try:
                            _code = Request(scope, receive).query_params.get('code')
                            if _code is None or len(_code) == 0:
                                raise Exception('no code found')
                            _token = _fetch_grant_token(config=oauth2_cookie_config, state=_cookie_data['state'],
                                                        code=_code)
                            _token = OAuth2Session(token=_token).access_token
                            response.set_cookie(
                                key=oauth2_cookie_name,
                                value=_create_token_cookie_data(oauth2_cookie_config, _token),
                                secure=True, samesite='none', httponly=True, expires='session',
                                # path=oauth2_cookie_path
                            )
                        except Exception as e:
                            # sth wrong
                            # delete cookie and redirect - will cause a loop but maybe next time it will work
                            response.delete_cookie(key=oauth2_cookie_name)
                        finally:
                            return response(scope, receive, send)
                    if _cookie_type == 'token':
                        # real cookie w/ auth data
                        cookie_data.update({oauth2_cookie_name: _cookie_data.get('token')})
                # else:
                #     # defect cookie / not our cookie > try again?
                #     pass
            else:
                # no cookie > do oauth2 redirect
                response = _create_oauth2_redirect_response(
                    scope=scope, receive=receive, name=oauth2_cookie_name, config=oauth2_cookie_config
                )
                return response(scope, receive, send)

    if len(cookie_data) > 0:
        merge_auth_info(scope, {'oauth2_cookie': cookie_data})
