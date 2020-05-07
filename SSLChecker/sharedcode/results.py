# Setters for the results dictionary


def set_error(error_type, message):
    return {'Error Type': error_type, "Message": message}


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
