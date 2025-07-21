from pydantic import ValidationError
import pytest

from app.schemas.user import UserCreate

def test_verify_password_match_success():
    user = UserCreate(
        first_name="John",
        last_name="Doe",
        email="john.doe@example.com",
        username="johndoe",
        password="SecurePass123!",
        confirm_password="SecurePass123!"
    )
    result = user.verify_password_match()
    assert result == user

def test_verify_password_match_failure():
    with pytest.raises(ValueError, match="Passwords do not match"):
        UserCreate(
            first_name="John",
            last_name="Doe",
            email="john.doe@example.com",
            username="johndoe",
            password="SecurePass123!",
            confirm_password="WrongPass123!"
        ).verify_password_match()


# A valid base user dict with all required fields except password
base_user_data = {
    "first_name": "John",
    "last_name": "Doe",
    "email": "john.doe@example.com",
    "username": "johndoe",
}

def test_validate_password_strength_success():
    user = UserCreate(
        **base_user_data,
        password="ValidPass1!",
        confirm_password="ValidPass1!"
    )
    # Call the validator explicitly
    result = user.validate_password_strength()
    assert result == user

@pytest.mark.parametrize(
    "bad_password, error_msg",
    [
        ("Short1!", "String should have at least 8 characters"),  # Pydantic's own message
    ],
)
def test_password_min_length_fails(bad_password, error_msg):
    with pytest.raises(ValidationError) as exc_info:
        UserCreate(
            **base_user_data,
            password=bad_password,
            confirm_password=bad_password
        )
    errors = exc_info.value.errors()
    error_texts = [err['msg'] for err in errors]
    assert any(error_msg in text for text in error_texts)

def test_password_uppercase_missing():
    bad_password = "lowercase1!"
    with pytest.raises(ValidationError) as exc_info:
        UserCreate(
            **base_user_data,
            password=bad_password,
            confirm_password=bad_password
        )
    errors = exc_info.value.errors()
    error_texts = [err['msg'] for err in errors]
    assert any("Password must contain at least one uppercase letter" in text for text in error_texts)