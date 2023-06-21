"""
General math functions
"""


def modular_exponentiation(base, exponent, modulus):
    """
    Calculates:
        (base**exponent) % modulus
    efficiently, which is required for for large numbers.

    Args:
        base (int)
        exponent (int)
        modulus (int)
    Returns:
        remainder (int). Where remainder = (base**exponent) % modulus
    """
    if modulus == 1:
        return 0

    result = 1
    b = base % modulus
    e = exponent

    while e > 0:
        if e % 2 == 1:
            result = (result * b) % modulus
        e = e // 2
        b = (b * b) % modulus
    return result


def modexp(b, e, m):
    """
    Calculates:
        (base**exponent) % modulus
    efficiently, which is required for for large numbers.

    Args:
        base (int)
        exponent (int)
        modulus (int)
    Returns:
        remainder (int). Where remainder = (base**exponent) % modulus
    """
    return modular_exponentiation(b, e, m)
