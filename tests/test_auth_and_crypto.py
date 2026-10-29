"""
Unit Tests: Authentication & Cryptographic Controls
Organization: Northbridge Cyber Response
Module: CYS22301 Software and Platform Security (Level 6)
"""

import pyotp
import pytest
from django.contrib.auth.hashers import identify_hasher

from accounts.models import CustomUser, UserRole


@pytest.mark.django_db
def test_argon2id_password_hashing():
    """
    Verifies that CaseVault uses Argon2id as the default password hasher (ADR-0001).
    Ensures memory-hard hashing algorithm is actively utilized for credential storage.
    """
    user = CustomUser.objects.create_user(
        username='argon_user',
        password='ValidPassword123!',
        role=UserRole.INVESTIGATOR
    )
    # Ensure password hash starts with the standard Argon2 identifier
    assert user.password.startswith('argon2'), f"Expected Argon2 hash, got: {user.password[:15]}"
    hasher = identify_hasher(user.password)
    assert hasher.algorithm == 'argon2'
    assert user.check_password('ValidPassword123!')
    assert not user.check_password('WrongPassword!')


@pytest.mark.django_db
def test_totp_generation_and_verification():
    """
    Tests RFC 6238 TOTP lifecycle: secret generation, token verification,
    and rejection of incorrect tokens.
    """
    user = CustomUser.objects.create_user(
        username='totp_user',
        password='ValidPassword123!',
        role=UserRole.INVESTIGATOR
    )
    secret = user.generate_totp_secret()
    assert len(secret) == 32  # Standard 32-character base32 secret

    totp = pyotp.TOTP(secret)
    current_token = totp.now()

    # Valid token verification
    assert user.verify_totp(current_token) is True

    # Invalid token verification
    assert user.verify_totp('000000') is False
    assert user.verify_totp('999999') is False
    assert user.verify_totp('') is False


@pytest.mark.django_db
def test_brute_force_account_lockout():
    """
    Verifies that 5 consecutive failed login attempts lock out the account.
    """
    user = CustomUser.objects.create_user(
        username='victim_user',
        password='TargetPassword123!',
        role=UserRole.INVESTIGATOR
    )

    assert user.is_account_locked() is False
    assert user.failed_login_attempts == 0

    # Simulate 4 failed attempts
    for i in range(4):
        user.record_failed_login(max_attempts=5, lockout_minutes=15)
        assert user.is_account_locked() is False
        assert user.failed_login_attempts == i + 1

    # 5th failed attempt triggers lockout
    user.record_failed_login(max_attempts=5, lockout_minutes=15)
    assert user.failed_login_attempts == 5
    assert user.is_account_locked() is True
    assert user.locked_until is not None

    # Reset on successful login
    user.reset_failed_logins()
    assert user.failed_login_attempts == 0
    assert user.is_account_locked() is False

