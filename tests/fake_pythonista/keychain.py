STORE = {}


def get_password(service, account):
    return STORE.get((service, account))


def set_password(service, account, password):
    STORE[(service, account)] = password


def delete_password(service, account):
    STORE.pop((service, account), None)
