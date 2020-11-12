""" Setters for the results dictionary """

from typing import Dict, Any


def set_error(error_type, message) -> Dict[str, str]:
    return {"Error Type": error_type, "Message": message}


def new_result_set() -> Dict[str, Any]:
    """ Result set """

    return {"Target": None, "IP": None, "MD5": None, "Scan": None, "View": None, "Results": []}


def set_result(results, key, value):
    results[key] = value


def set_ciphers(results, value):
    results["Results"].append(value)
