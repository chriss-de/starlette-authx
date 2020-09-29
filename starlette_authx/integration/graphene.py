from graphql import GraphQLError

from starlette_authx import utils


def gql_field_protect(condition='False'):
    def inner(function):
        def wrapper(obj, info, **kwargs):
            if utils.validator(condition, info.context['request'].scope.get('authx', {})):
                return function(obj, info, **kwargs)
            else:
                raise GraphQLError(f"unauthorized - no access to field '{info.field_name}'")
        return wrapper
    return inner
