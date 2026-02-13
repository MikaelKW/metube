import base64
import hashlib
import hmac
import json
import logging
import os
import re
import tempfile
import threading
import time
from http.cookies import SimpleCookie
from pathlib import Path


log = logging.getLogger("auth")

USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{2,31}$")
VALID_ROLES = {"admin", "user"}
PASSWORD_HASH_ITERATIONS = 390000


def _b64_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64_decode(encoded: str) -> bytes:
    padding = "=" * (-len(encoded) % 4)
    return base64.urlsafe_b64decode(encoded + padding)


def validate_username(username: str) -> None:
    if not USERNAME_PATTERN.match(username):
        raise ValueError(
            "Username must be 3-32 characters and contain only letters, numbers, '.', '_' or '-'."
        )


def validate_password(password: str) -> None:
    if len(password or "") < 8:
        raise ValueError("Password must be at least 8 characters long.")
    if password.strip() == "":
        raise ValueError("Password must contain non-space characters.")


def hash_password(password: str, iterations: int = PASSWORD_HASH_ITERATIONS) -> str:
    validate_password(password)
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"pbkdf2_sha256${iterations}${_b64_encode(salt)}${_b64_encode(digest)}"


def verify_password(password: str, encoded_hash: str) -> bool:
    try:
        algorithm, iterations_s, salt_s, digest_s = encoded_hash.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        iterations = int(iterations_s)
        salt = _b64_decode(salt_s)
        expected_digest = _b64_decode(digest_s)
    except (ValueError, TypeError):
        return False

    actual_digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return hmac.compare_digest(actual_digest, expected_digest)


class UserStore:
    def __init__(self, path: str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def _load_unlocked(self) -> dict:
        if not self.path.exists():
            return {"users": []}
        with self.path.open("r", encoding="utf-8") as file_handle:
            data = json.load(file_handle)
        if not isinstance(data, dict):
            raise RuntimeError(f"Invalid users file structure: {self.path}")
        users = data.get("users", [])
        if not isinstance(users, list):
            raise RuntimeError(f"Invalid users list in: {self.path}")
        data["users"] = users
        return data

    def _write_unlocked(self, data: dict) -> None:
        temp_fd, temp_path = tempfile.mkstemp(prefix="users-", suffix=".json", dir=self.path.parent)
        try:
            with os.fdopen(temp_fd, "w", encoding="utf-8") as temp_file:
                json.dump(data, temp_file, indent=2, sort_keys=True)
                temp_file.flush()
                os.fsync(temp_file.fileno())
            os.replace(temp_path, self.path)
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def _public_user(self, user_record: dict) -> dict:
        return {"username": user_record["username"], "role": user_record["role"]}

    def _session_version(self, user_record: dict) -> int:
        return int(user_record.get("password_updated_at") or user_record.get("created_at") or 0)

    def _next_session_version(self, user_record: dict) -> int:
        # Guarantee monotonic session version increments so rapid password
        # changes still invalidate all existing sessions.
        now = int(time.time())
        current = self._session_version(user_record)
        return now if now > current else (current + 1)

    def _session_user(self, user_record: dict) -> dict:
        return {
            "username": user_record["username"],
            "role": user_record["role"],
            "session_version": self._session_version(user_record),
        }

    def list_users(self) -> list[dict]:
        with self._lock:
            data = self._load_unlocked()
        users = [self._public_user(user) for user in data["users"]]
        users.sort(key=lambda entry: entry["username"])
        return users

    def get_user(self, username: str) -> dict | None:
        with self._lock:
            data = self._load_unlocked()
            for user in data["users"]:
                if user["username"] == username:
                    return self._public_user(user)
        return None

    def get_session_user(self, username: str) -> dict | None:
        with self._lock:
            data = self._load_unlocked()
            for user in data["users"]:
                if user["username"] == username:
                    return self._session_user(user)
        return None

    def ensure_bootstrap_admin(self, username: str, password: str) -> None:
        with self._lock:
            data = self._load_unlocked()
            if data["users"]:
                return
            if not username or not password:
                raise RuntimeError(
                    "ENABLE_AUTH is true and no users exist. Set AUTH_ADMIN_USERNAME and AUTH_ADMIN_PASSWORD to bootstrap the first admin user."
                )
            validate_username(username)
            validate_password(password)
            data["users"].append(
                {
                    "username": username,
                    "role": "admin",
                    "password_hash": hash_password(password),
                    "created_at": int(time.time()),
                }
            )
            self._write_unlocked(data)
            log.info("Created bootstrap admin user '%s'", username)

    def create_user(self, username: str, password: str, role: str = "user") -> dict:
        validate_username(username)
        validate_password(password)
        if role not in VALID_ROLES:
            raise ValueError(f"Role must be one of: {', '.join(sorted(VALID_ROLES))}")

        with self._lock:
            data = self._load_unlocked()
            if any(user["username"] == username for user in data["users"]):
                raise ValueError(f"User '{username}' already exists.")

            new_user = {
                "username": username,
                "role": role,
                "password_hash": hash_password(password),
                "created_at": int(time.time()),
            }
            data["users"].append(new_user)
            self._write_unlocked(data)
            return self._public_user(new_user)

    def delete_user(self, username: str) -> dict:
        validate_username(username)

        with self._lock:
            data = self._load_unlocked()
            users = data["users"]
            index = next((i for i, user in enumerate(users) if user["username"] == username), None)
            if index is None:
                raise KeyError(f"User '{username}' not found.")

            target = users[index]
            if target["role"] == "admin":
                admin_count = sum(1 for user in users if user.get("role") == "admin")
                if admin_count <= 1:
                    raise ValueError("Cannot delete the last admin user.")

            deleted_user = self._public_user(target)
            del users[index]
            self._write_unlocked(data)
            return deleted_user

    def verify_credentials(self, username: str, password: str) -> dict | None:
        with self._lock:
            data = self._load_unlocked()
            for user in data["users"]:
                if user["username"] != username:
                    continue
                if verify_password(password, user.get("password_hash", "")):
                    return self._public_user(user)
                return None
        return None

    def verify_credentials_session(self, username: str, password: str) -> dict | None:
        with self._lock:
            data = self._load_unlocked()
            for user in data["users"]:
                if user["username"] != username:
                    continue
                if verify_password(password, user.get("password_hash", "")):
                    return self._session_user(user)
                return None
        return None

    def verify_user_password(self, username: str, password: str) -> bool:
        with self._lock:
            data = self._load_unlocked()
            for user in data["users"]:
                if user["username"] != username:
                    continue
                return verify_password(password, user.get("password_hash", ""))
        return False

    def set_password(self, username: str, new_password: str) -> dict:
        validate_username(username)
        validate_password(new_password)

        with self._lock:
            data = self._load_unlocked()
            for user in data["users"]:
                if user["username"] != username:
                    continue
                user["password_hash"] = hash_password(new_password)
                user["password_updated_at"] = self._next_session_version(user)
                self._write_unlocked(data)
                return self._public_user(user)
        raise KeyError(f"User '{username}' not found.")


class SessionManager:
    def __init__(self, secret: str, ttl_seconds: int, cookie_name: str = "metube_session"):
        if not secret:
            raise ValueError("Session secret cannot be empty.")
        self._secret = secret.encode("utf-8")
        self.ttl_seconds = ttl_seconds
        self.cookie_name = cookie_name

    def _sign(self, payload: str) -> str:
        return _b64_encode(hmac.new(self._secret, payload.encode("utf-8"), hashlib.sha256).digest())

    def create_token(self, user: dict) -> str:
        payload = json.dumps(
            {
                "username": user["username"],
                "role": user["role"],
                "sv": int(user.get("session_version", 0)),
                "exp": int(time.time()) + self.ttl_seconds,
            },
            separators=(",", ":"),
            sort_keys=True,
        )
        payload_token = _b64_encode(payload.encode("utf-8"))
        signature = self._sign(payload_token)
        return f"{payload_token}.{signature}"

    def parse_token(self, token: str) -> dict | None:
        try:
            payload_token, signature = token.split(".", 1)
        except ValueError:
            return None

        expected_signature = self._sign(payload_token)
        if not hmac.compare_digest(signature, expected_signature):
            return None

        try:
            payload_raw = _b64_decode(payload_token)
            payload = json.loads(payload_raw)
            exp = int(payload["exp"])
            username = payload["username"]
            role = payload["role"]
            session_version = int(payload.get("sv", 0))
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            return None

        if exp <= int(time.time()):
            return None
        if role not in VALID_ROLES:
            return None
        if not isinstance(username, str) or not USERNAME_PATTERN.match(username):
            return None

        return {"username": username, "role": role, "session_version": session_version}

    def user_from_request(self, request) -> dict | None:
        token = request.cookies.get(self.cookie_name)
        if not token:
            return None
        return self.parse_token(token)

    def user_from_environ(self, environ: dict) -> dict | None:
        cookie_header = environ.get("HTTP_COOKIE", "")
        if not cookie_header:
            return None
        parsed = SimpleCookie()
        parsed.load(cookie_header)
        morsel = parsed.get(self.cookie_name)
        if morsel is None:
            return None
        return self.parse_token(morsel.value)

    def set_cookie(self, response, user: dict) -> None:
        token = self.create_token(user)
        response.set_cookie(
            self.cookie_name,
            token,
            httponly=True,
            max_age=self.ttl_seconds,
            path="/",
            samesite="Lax",
        )

    def clear_cookie(self, response) -> None:
        response.del_cookie(self.cookie_name, path="/")
