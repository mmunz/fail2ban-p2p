import re

def isInteger(n):
    '''Check if a value is an integer

    Args:
        * n: the value that should be checked

    Returns:
        * False: Value is no integer
        * True: Value is integer 
    '''
    try:
        # convert to string before testing to convert to int
        # without this also False and True would pass here
        int(str(n))
        return True
    except ValueError:
        return False

def isAlphaNumeric(str):
    '''Check if a string only contains alphanumeric characters

    Args:
        * str: the value that should be checked

    Returns:
        * False: String is not alphanumeric
        * True: String is aplhanumeric
    '''

    try:
        if re.match('^[A-Za-z0-9]*$', str):
            return True
        else:
            raise
    except:
        return False

def isIPv4address(str):
    '''Check if a string is a valid IPv4 address

    Args:
        * str: the string that should be checked

    Returns:
        * False: String is not an IPv4 address
        * True: String is an IPv4 address
    '''

    try:
        reIPv4 = "(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
        if re.match(reIPv4, str):
            return True
        else:
            raise
    except:
        return False

isIPv4address('1.2.3.300')
