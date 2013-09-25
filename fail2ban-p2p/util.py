# Copyright 2013 Johannes Fuermann <johannes at fuermann.cc>
# Copyright 2013 Manuel Munz <manu at somakoma.de>
#
# This file is part of fail2ban-p2p.
#
# Licensed under the GNU GENERAL PUBLIC LICENSE Version 3. For details
# see the file COPYING or http://www.gnu.org/licenses/gpl-3.0.en.html.

from odict import OrderedDict

def sort_recursive(dictionary):
    """
    Recursively sorts nested dictionaries. Should not be applied if the
    structures are nested too deeply and/or there is even the remote
    possibility that the nesting of the passed dictionary contains a cyclic
    structure.

    Args:
        dictionary (dict): A python dictionary

    Returns:
        A recursively sorted dictionary

    Example:

    >>> dict = { 'a': '2', 'c': 3, 'b': { 'e': 4, 'd': 1 }, 'f': 5}
    >>> sort_recursive(dict)
    OrderedDict([('a', '2'), ('b', OrderedDict([('d', 1), ('e', 4)])), ('c', 3), ('f', 5)])

    """
    sorted_list = OrderedDict(sorted(dictionary.items(), key = lambda x: x[0]))
    # TODO test for cyclic structures.
    for key, value in sorted_list.items():
        if type(value) is dict:
            sorted_list[key] = sort_recursive(value)

    return sorted_list

if __name__ == '__main__':
    import doctest
    doctest.testmod()
