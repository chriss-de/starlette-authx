import json
import urllib.request
import jose.jwt
import logging
from starlette.requests import Request
from starlette.types import Receive, Scope, Send
from . import InvalidToken, merge_auth_info

_jwt_keys = {}

"""
this stuff is mostly from https://gitlab.com/jorgecarleitao/starlette-oauth2-api
"""


def validate_config(config):
    providers = config.get('providers')
    mandatory_keys = {'issuer', 'keys', 'audience'}
    for provider in providers:
        if not mandatory_keys.issubset(set(providers[provider])):
            raise ValueError(
                f'Each provider must contain the following keys: {mandatory_keys}. Provider "{provider}" is missing {mandatory_keys - set(providers[provider])}.')

        keys = providers[provider]['keys']
        if isinstance(keys, str) and keys.startswith('http://'):
            raise ValueError(
                f'When "keys" is a url, it must start with "https://". This is not true in the provider "{provider}"')


def _get_keys(url_or_keys):
    if isinstance(url_or_keys, str) and url_or_keys.startswith('https://'):
        with urllib.request.urlopen(url_or_keys) as f:
            return json.loads(f.read().decode())
    else:
        return url_or_keys


async def process(config, scope: Scope, receive: Receive, send: Send) -> None:
    """
    this stuff is mostly from https://gitlab.com/jorgecarleitao/starlette-oauth2-api
    """
    client_bearer_auth_results = {}
    request = Request(scope)

    # check for authorization header and token on it.
    if 'authorization' in request.headers and request.headers['authorization'].startswith('Bearer '):
        token = request.headers['authorization'][len('Bearer '):]
        providers = config.get('providers')
        for provider in providers:
            try:
                result = _provider_claims(provider, providers[provider], token)
                if len(client_bearer_auth_results) == 1:
                    logging.warning(f"more than one provider matches that token. looks like a config error.")
                else:
                    client_bearer_auth_results = result
                    client_bearer_auth_results['__provider_name'] = provider
            except jose.exceptions.JWSError as e:
                raise InvalidToken(str(e))
            except jose.exceptions.JWTClaimsError as e:
                pass
            except jose.exceptions.JWTError as e:
                raise InvalidToken(str(e))
            except jose.exceptions.JOSEError as e:
                logging.debug(str(e))

    if len(client_bearer_auth_results) > 0:
        merge_auth_info(scope, {'bearer': client_bearer_auth_results})


def _provider_claims(provider_name, provider, token):
    """

    """
    return jose.jwt.decode(
        token, _provider_keys(provider_name, provider),
        issuer=provider['issuer'],
        audience=provider['audience'],
        options={'verify_at_hash': False}
    )


def _provider_keys(provider_name, provider):
    """
    Returns the signing keys of the provider
    """
    if _jwt_keys.get(provider_name, None) is None:
        _jwt_keys[provider_name] = _get_keys(provider['keys'])
    return _jwt_keys[provider_name]
