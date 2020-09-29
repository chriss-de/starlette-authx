
class InvalidToken(Exception):
    pass


def dict_merge(base_dct, merge_dct):
    base_dct.update({
        key: dict_merge(base_dct[key], merge_dct[key])
        if isinstance(base_dct.get(key), dict) and isinstance(merge_dct[key], dict)
        else merge_dct[key]
        for key in merge_dct.keys()
    })


def merge_auth_info(scope, data):
    if data is not None:
        if 'authx' not in scope:
            scope['authx'] = {}
        dict_merge(scope['authx'], data)
