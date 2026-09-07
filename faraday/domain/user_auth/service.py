"""User auth domain service — YAGNI extraction from User/Role.

Pure helpers: normalize_username, is_active_check.
Mantiene contrato audit login faraday/server/app.py:726 CustomLoginForm.
"""
import re

def normalize_username(username: str) -> str:
    return (username or "").strip()

def is_valid_password_format(password: str) -> bool:
    # mirrors PASSWORD_REGEX faraday/server/app.py:115
    import re
    return bool(re.match(r'^(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9])(?=.*[~!@#$%^&*_\-+=|(){}\[\]:";\'<>,.?/]).{8,}$', password or ""))

