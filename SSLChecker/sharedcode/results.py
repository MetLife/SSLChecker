# Setters for the results dictionary


def set_error(name, message):
    global _error
    _error = {}
    _error = {"Hostname": name, "Message": message}
    return _error


def new():
    return {
            'Hostname':     None,
            'IP':           None,
            'MD5':          None,
            'View':         None,
            'Results':      []
            }


def set_result(results, key, value):
    results[key] = value


def set_ciphers(results, value):
    results['Results'].append(value)
