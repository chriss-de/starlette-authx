from jinja2 import Environment
from jinja2.utils import contextfunction


def _get_authx_config(context, name):
    return context.parent.get('authx', {}).get(name, {})


def has_ipaccess(context, name):
    config = _get_authx_config(context, 'ipaccess')
    if (name is None and len(config) > 0) or name in config:
        return True
    return False


def has_token_attr(context, key, value):
    config = _get_authx_config(context, 'bearer')
    if value == config.get(key, ""):
        return True
    return False


def is_bearer_auth(context):
    config = _get_authx_config(context, 'bearer')
    if len(config) > 0:
        return True
    return False


def has_basic_auth(context):
    config = _get_authx_config(context, 'basic')
    if len(config) > 0:
        return True
    return False


def is_basic_user(context, user):
    config = _get_authx_config(context, 'basic')
    if config.get('username') == user:
        return True
    return False


def has_basic_group(context, group):
    config = _get_authx_config(context, 'basic')
    if group in config.get('groups', []):
        return True
    return False


def has_any_auth(context):
    if len(context.parent.get('authx', {})) > 0:
        return True
    return False


_environment = Environment()
_environment.globals.update(
    {
        'has_ipaccess': contextfunction(has_ipaccess),
        'is_bearer_auth': contextfunction(is_bearer_auth),
        'has_token_attr': contextfunction(has_token_attr),
        'has_basic_auth': contextfunction(has_basic_auth),
        'is_basic_user': contextfunction(is_basic_user),
        'has_basic_group': contextfunction(has_basic_group),
        'has_any_auth': contextfunction(has_any_auth)
    }
)


def validator(condition="False", config={}) -> bool:
    template = _environment.from_string(f"{{{{ {condition} }}}}")
    result = template.render(authx=config)
    return False if result != 'True' else True
