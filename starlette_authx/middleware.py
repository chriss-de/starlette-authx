from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Scope, Receive, Send
import asyncio
from . import ipaccess, basic, bearer, utils, InvalidToken, oauth2_cookie


class AuthXMiddleware:
    _AUTH_METHODS = {
        'ipaccess': ipaccess,
        'bearer': bearer,
        'basic': basic,
        'oauth2_cookie': oauth2_cookie,
    }
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

    def _validate_config(self):
        for method in self._AUTH_METHODS.keys():
            if method in self._config:
                if 'validate_config' in dir(self._AUTH_METHODS[method]):
                    self._AUTH_METHODS[method].validate_config(self._config[method])

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        try:
            for method in self._AUTH_METHODS.keys():
                if method in self._config:
                    _config = self._config[method]
                    result = await self._AUTH_METHODS[method].process(_config, scope, receive, send)
                    if asyncio.iscoroutine(result):
                        return await result

            # check current request for general auth actions
            if scope['path'] in self._known_paths.keys():
                if not utils.validator(condition=self._known_paths[scope['path']], config=scope.get('authx', {})):
                    response = JSONResponse({'message': 'unauthorized'}, status_code=401)
                    return await response(scope, receive, send)

            await self._app(scope, receive, send)

        except InvalidToken as e:
            response = JSONResponse({'message': str(e)}, status_code=401)
            await response(scope, receive, send)
