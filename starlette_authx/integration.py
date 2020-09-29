from fastapi import HTTPException
from graphql import GraphQLError
from starlette.requests import Request

from starlette_authx import utils
from starlette_authx.utils import validator


class AuthXFastAPIDepends:
    def __init__(self, condition: str = "False"):
        self._condition = condition

    async def __call__(self, request: Request) -> None:
        result = validator(self._condition, config=request.scope.get('authx', {}))
        if not result:
            raise HTTPException(status_code=401)


def gql_field_protect(condition='False'):
    def inner(function):
        def wrapper(obj, info, **kwargs):
            if utils.validator(condition, info.context['request'].scope.get('authx', {})):
                return function(obj, info, **kwargs)
            else:
                raise GraphQLError(f"unauthorized - no access to field '{info.field_name}'")
        return wrapper
    return inner
