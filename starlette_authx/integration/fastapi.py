from fastapi import HTTPException
from starlette.requests import Request

from starlette_authx.utils import validator


class AuthXFastAPIDepends:
    def __init__(self, condition: str = "False"):
        self._condition = condition

    async def __call__(self, request: Request) -> None:
        result = validator(self._condition, config=request.scope.get('authx', {}))
        if not result:
            raise HTTPException(status_code=401)
