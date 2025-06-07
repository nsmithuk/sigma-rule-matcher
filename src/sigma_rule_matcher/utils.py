
def get_by_dots(d: dict, key: str, default=None):
    try:
        for part in key.split('.'):
            d = d[part]
    except (KeyError, TypeError):
        return default
    else:
        return d
