import pytest
from api.auth.register import validate_password

def test_password_validation():
    # Length
    assert not validate_password("Short1!")
    assert not validate_password("a" * 73 + "A1!")
    # Complexity
    assert not validate_password("nouppercase1!")
    assert not validate_password("NOLOWERCASE1!")
    assert not validate_password("NoNumbersHere!")
    assert not validate_password("NoSpecialChar123")
    # Valid
    assert validate_password("ValidPassword123!")
    assert validate_password("Another!2Strong")
