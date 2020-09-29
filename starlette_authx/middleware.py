from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Scope, Receive, Send

from . import ipaccess, merge_auth_info, basic, bearer, utils, InvalidToken


class AuthXMiddleware:
    # TODO: from config/modifiable
    _known_paths = {
        '/docs': 'has_any_auth()',
        '/redoc': 'has_any_auth()',
        '/openapi.json': 'has_any_auth()',
        '/graphql': 'has_any_auth()'
    }

    def __init__(self, app: ASGIApp, config: dict) -> None:
        self._app = app
        self._config = config
        self._validate_config()

    # TODO: validate all config - not just bearer
    def _validate_config(self):
        """
        this stuff is mostly from https://gitlab.com/jorgecarleitao/starlette-oauth2-api
        """
        if 'bearer' in self._config:
            providers = self._config.get('bearer').get('providers')
            mandatory_keys = {'issuer', 'keys', 'audience'}
            for provider in providers:
                if not mandatory_keys.issubset(set(providers[provider])):
                    raise ValueError(
                        f'Each provider must contain the following keys: {mandatory_keys}. Provider "{provider}" is missing {mandatory_keys - set(providers[provider])}.')

                keys = providers[provider]['keys']
                if isinstance(keys, str) and keys.startswith('http://'):
                    raise ValueError(
                        f'When "keys" is a url, it must start with "https://". This is not true in the provider "{provider}"')

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        try:
            if 'ipaccess' in self._config:
                result = ipaccess.process(self._config.get('ipaccess'), scope, receive, send)
                if len(result) > 0:
                    merge_auth_info(scope, {'ipaccess': result})
            if 'basic' in self._config:
                result = basic.process(self._config.get('basic'), scope, receive, send)
                if 'username' in result:
                    merge_auth_info(scope, {'basic': result})
            if 'bearer' in self._config:
                result = bearer.process(self._config.get('bearer'), scope, receive, send)
                if len(result) > 0:
                    merge_auth_info(scope, {'bearer': result})

            # fetched all auth data
            # check current request for general auth actions
            if scope['path'] in self._known_paths.keys():
                if not utils.validator(condition=self._known_paths[scope['path']], config=scope.get('authx', {})):
                    response = JSONResponse({'message': 'unauthorized'}, status_code=401)
                    return await response(scope, receive, send)

            return await self._app(scope, receive, send)

        except InvalidToken as e:
            response = JSONResponse({'message': str(e)}, status_code=401)
            return await response(scope, receive, send)
