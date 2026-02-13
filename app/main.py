#!/usr/bin/env python3
# pylint: disable=no-member,method-hidden

import os
import sys
import asyncio
import copy
import shutil
from pathlib import Path
from aiohttp import web
from aiohttp.log import access_logger
import ssl
import socket
import socketio
import logging
import json
import pathlib
import re
from urllib.parse import unquote
from watchfiles import DefaultFilter, Change, awatch

from auth import SessionManager, UserStore
from ytdl import DownloadQueueNotifier, DownloadQueue
from yt_dlp.version import __version__ as yt_dlp_version

log = logging.getLogger('main')

def parseLogLevel(logLevel):
    match logLevel:
        case 'DEBUG':
            return logging.DEBUG
        case 'INFO':
            return logging.INFO
        case 'WARNING':
            return logging.WARNING
        case 'ERROR':
            return logging.ERROR
        case 'CRITICAL':
            return logging.CRITICAL
        case _:
            return None

# Configure logging before Config() uses it so early messages are not dropped.
# Only configure if no handlers are set (avoid clobbering hosting app settings).
if not logging.getLogger().hasHandlers():
    logging.basicConfig(level=parseLogLevel(os.environ.get('LOGLEVEL', 'INFO')) or logging.INFO)

class Config:
    _DEFAULTS = {
        'DOWNLOAD_DIR': '.',
        'AUDIO_DOWNLOAD_DIR': '%%DOWNLOAD_DIR',
        'TEMP_DIR': '%%DOWNLOAD_DIR',
        'DOWNLOAD_DIRS_INDEXABLE': 'false',
        'CUSTOM_DIRS': 'true',
        'CREATE_CUSTOM_DIRS': 'true',
        'CUSTOM_DIRS_EXCLUDE_REGEX': r'(^|/)[.@].*$',
        'DELETE_FILE_ON_TRASHCAN': 'false',
        'STATE_DIR': '.',
        'URL_PREFIX': '',
        'PUBLIC_HOST_URL': 'download/',
        'PUBLIC_HOST_AUDIO_URL': 'audio_download/',
        'OUTPUT_TEMPLATE': '%(title)s.%(ext)s',
        'OUTPUT_TEMPLATE_CHAPTER': '%(title)s - %(section_number)02d - %(section_title)s.%(ext)s',
        'OUTPUT_TEMPLATE_PLAYLIST': '%(playlist_title)s/%(title)s.%(ext)s',
        'OUTPUT_TEMPLATE_CHANNEL': '%(channel)s/%(title)s.%(ext)s',
        'DEFAULT_OPTION_PLAYLIST_ITEM_LIMIT' : '0',
        'YTDL_OPTIONS': '{}',
        'YTDL_OPTIONS_FILE': '',
        'ROBOTS_TXT': '',
        'HOST': '0.0.0.0',
        'PORT': '8081',
        'HTTPS': 'false',
        'CERTFILE': '',
        'KEYFILE': '',
        'BASE_DIR': '',
        'DEFAULT_THEME': 'auto',
        'MAX_CONCURRENT_DOWNLOADS': 3,
        'LOGLEVEL': 'INFO',
        'ENABLE_ACCESSLOG': 'false',
        'ENABLE_AUTH': 'false',
        'AUTH_USERS_FILE': 'users.json',
        'AUTH_ADMIN_USERNAME': '',
        'AUTH_ADMIN_PASSWORD': '',
        'AUTH_SESSION_SECRET': '',
        'AUTH_SESSION_TTL': '2592000',
    }

    _BOOLEAN = (
        'DOWNLOAD_DIRS_INDEXABLE',
        'CUSTOM_DIRS',
        'CREATE_CUSTOM_DIRS',
        'DELETE_FILE_ON_TRASHCAN',
        'HTTPS',
        'ENABLE_ACCESSLOG',
        'ENABLE_AUTH',
    )

    def __init__(self):
        for k, v in self._DEFAULTS.items():
            setattr(self, k, os.environ.get(k, v))

        for k, v in self.__dict__.items():
            if isinstance(v, str) and v.startswith('%%'):
                setattr(self, k, getattr(self, v[2:]))
            if k in self._BOOLEAN:
                if v not in ('true', 'false', 'True', 'False', 'on', 'off', '1', '0'):
                    log.error(f'Environment variable "{k}" is set to a non-boolean value "{v}"')
                    sys.exit(1)
                setattr(self, k, v in ('true', 'True', 'on', '1'))

        if not self.URL_PREFIX.endswith('/'):
            self.URL_PREFIX += '/'

        # Keep users file inside STATE_DIR by default when a relative path is used.
        if self.AUTH_USERS_FILE and not os.path.isabs(self.AUTH_USERS_FILE):
            self.AUTH_USERS_FILE = os.path.join(self.STATE_DIR, self.AUTH_USERS_FILE)

        # Convert relative addresses to absolute addresses to prevent the failure of file address comparison
        if self.YTDL_OPTIONS_FILE and self.YTDL_OPTIONS_FILE.startswith('.'):
            self.YTDL_OPTIONS_FILE = str(Path(self.YTDL_OPTIONS_FILE).resolve())

        success,_ = self.load_ytdl_options()
        if not success:
            sys.exit(1)

        try:
            self.AUTH_SESSION_TTL = int(self.AUTH_SESSION_TTL)
        except ValueError:
            log.error('Environment variable "AUTH_SESSION_TTL" must be an integer value in seconds')
            sys.exit(1)
        if self.AUTH_SESSION_TTL <= 0:
            log.error('Environment variable "AUTH_SESSION_TTL" must be greater than zero')
            sys.exit(1)

    def load_ytdl_options(self) -> tuple[bool, str]:
        try:
            self.YTDL_OPTIONS = json.loads(os.environ.get('YTDL_OPTIONS', '{}'))
            assert isinstance(self.YTDL_OPTIONS, dict)
        except (json.decoder.JSONDecodeError, AssertionError):
            msg = 'Environment variable YTDL_OPTIONS is invalid'
            log.error(msg)
            return (False, msg)

        if not self.YTDL_OPTIONS_FILE:
            return (True, '')

        log.info(f'Loading yt-dlp custom options from "{self.YTDL_OPTIONS_FILE}"')
        if not os.path.exists(self.YTDL_OPTIONS_FILE):
            msg = f'File "{self.YTDL_OPTIONS_FILE}" not found'
            log.error(msg)
            return (False, msg)
        try:
            with open(self.YTDL_OPTIONS_FILE) as json_data:
                opts = json.load(json_data)
            assert isinstance(opts, dict)
        except (json.decoder.JSONDecodeError, AssertionError):
            msg = 'YTDL_OPTIONS_FILE contents is invalid'
            log.error(msg)
            return (False, msg)

        self.YTDL_OPTIONS.update(opts)
        return (True, '')

config = Config()
# Align root logger level with Config (keeps a single source of truth).
# This re-applies the log level after Config loads, in case LOGLEVEL was
# overridden by config file settings or differs from the environment variable.
logging.getLogger().setLevel(parseLogLevel(str(config.LOGLEVEL)) or logging.INFO)

class ObjectSerializer(json.JSONEncoder):
    def default(self, obj):
        # First try to use __dict__ for custom objects
        if hasattr(obj, '__dict__'):
            return obj.__dict__
        # Convert iterables (generators, dict_items, etc.) to lists
        # Exclude strings and bytes which are also iterable
        elif hasattr(obj, '__iter__') and not isinstance(obj, (str, bytes)):
            try:
                return list(obj)
            except:
                pass
        # Fall back to default behavior
        return json.JSONEncoder.default(self, obj)

serializer = ObjectSerializer()
user_store = None
session_manager = None

if config.ENABLE_AUTH:
    try:
        user_store = UserStore(config.AUTH_USERS_FILE)
        user_store.ensure_bootstrap_admin(config.AUTH_ADMIN_USERNAME, config.AUTH_ADMIN_PASSWORD)
        session_secret = config.AUTH_SESSION_SECRET
        if not session_secret:
            # Deliberately allow ephemeral sessions if the secret is omitted.
            # Existing sessions will be invalid after each restart in this mode.
            session_secret = os.urandom(32).hex()
            log.warning(
                "AUTH_SESSION_SECRET is not set; sessions will be invalidated on restart."
            )
        session_manager = SessionManager(session_secret, config.AUTH_SESSION_TTL)
    except Exception as exc:
        log.error("Failed to initialize authentication subsystem: %s", exc)
        sys.exit(1)


def _route_with_prefix(path: str) -> str:
    return config.URL_PREFIX + path


_AUTH_PROTECTED_EXACT_PATHS = {
    _route_with_prefix('add'),
    _route_with_prefix('delete'),
    _route_with_prefix('start'),
    _route_with_prefix('history'),
    _route_with_prefix('auth/users'),
}
_AUTH_PROTECTED_PREFIX_PATHS = (
    _route_with_prefix('download/'),
    _route_with_prefix('audio_download/'),
    _route_with_prefix('socket.io'),
    _route_with_prefix('auth/users/'),
)


@web.middleware
async def auth_middleware(request, handler):
    request['auth_user'] = None
    if not config.ENABLE_AUTH:
        return await handler(request)

    session_user = session_manager.user_from_request(request) if session_manager is not None else None
    user = None
    if session_user is not None and user_store is not None:
        persisted_user = user_store.get_session_user(session_user['username'])
        if (
            persisted_user is not None
            and persisted_user.get('session_version') == session_user.get('session_version')
        ):
            # Always trust currently stored role over cookie role.
            user = public_user_from_session_user(persisted_user)
    if user is not None:
        request['auth_user'] = user

    path = request.path
    is_protected = (
        path in _AUTH_PROTECTED_EXACT_PATHS
        or any(path.startswith(prefix) for prefix in _AUTH_PROTECTED_PREFIX_PATHS)
    )

    if is_protected and user is None:
        raise web.HTTPUnauthorized()

    return await handler(request)


app = web.Application(middlewares=[auth_middleware] if config.ENABLE_AUTH else [])
sio = socketio.AsyncServer(cors_allowed_origins='*')
sio.attach(app, socketio_path=config.URL_PREFIX + 'socket.io')
routes = web.RouteTableDef()


def get_client_config(user=None):
    cfg = {
        k: v for k, v in config.__dict__.items()
        if not k.startswith('_')
    }
    for internal_key in (
        'AUTH_ADMIN_USERNAME',
        'AUTH_ADMIN_PASSWORD',
        'AUTH_SESSION_SECRET',
        'AUTH_USERS_FILE',
    ):
        cfg.pop(internal_key, None)
    cfg['AUTH_ENABLED'] = config.ENABLE_AUTH
    if user is not None:
        cfg['AUTH_USER'] = user
    return cfg


class Notifier(DownloadQueueNotifier):
    def __init__(self, room=None):
        self.room = room

    async def _emit(self, event, payload):
        if self.room is not None:
            await sio.emit(event, payload, to=self.room)
        else:
            await sio.emit(event, payload)

    async def added(self, dl):
        log.info(f"Notifier: Download added - {dl.title}")
        await self._emit('added', serializer.encode(dl))

    async def updated(self, dl):
        log.debug(f"Notifier: Download updated - {dl.title}")
        await self._emit('updated', serializer.encode(dl))

    async def completed(self, dl):
        log.info(f"Notifier: Download completed - {dl.title}")
        await self._emit('completed', serializer.encode(dl))

    async def canceled(self, id):
        log.info(f"Notifier: Download canceled - {id}")
        await self._emit('canceled', serializer.encode(id))

    async def cleared(self, id):
        log.info(f"Notifier: Download cleared - {id}")
        await self._emit('cleared', serializer.encode(id))


class UserQueueRegistry:
    def __init__(self, base_config):
        self.base_config = base_config
        self._queues = {}
        self._lock = asyncio.Lock()

    def room(self, username):
        return f'user:{username}'

    def _user_path(self, base_dir, username):
        return os.path.join(base_dir, username)

    def user_paths(self, username):
        download_dir = self._user_path(self.base_config.DOWNLOAD_DIR, username)

        if self.base_config.AUDIO_DOWNLOAD_DIR == self.base_config.DOWNLOAD_DIR:
            audio_download_dir = download_dir
        else:
            audio_download_dir = self._user_path(self.base_config.AUDIO_DOWNLOAD_DIR, username)

        if self.base_config.TEMP_DIR == self.base_config.DOWNLOAD_DIR:
            temp_dir = download_dir
        else:
            temp_dir = self._user_path(self.base_config.TEMP_DIR, username)

        state_dir = os.path.join(self.base_config.STATE_DIR, 'users', username)
        return {
            'download_dir': download_dir,
            'audio_download_dir': audio_download_dir,
            'temp_dir': temp_dir,
            'state_dir': state_dir,
        }

    def _build_user_config(self, username):
        paths = self.user_paths(username)
        user_config = copy.copy(self.base_config)
        user_config.DOWNLOAD_DIR = paths['download_dir']
        user_config.AUDIO_DOWNLOAD_DIR = paths['audio_download_dir']
        user_config.TEMP_DIR = paths['temp_dir']
        user_config.STATE_DIR = paths['state_dir']
        for directory in (
            user_config.DOWNLOAD_DIR,
            user_config.AUDIO_DOWNLOAD_DIR,
            user_config.TEMP_DIR,
            user_config.STATE_DIR,
        ):
            os.makedirs(directory, exist_ok=True)

        return user_config

    async def get(self, username):
        queue = self._queues.get(username)
        if queue is not None:
            return queue

        async with self._lock:
            queue = self._queues.get(username)
            if queue is not None:
                return queue
            user_config = self._build_user_config(username)
            queue = DownloadQueue(user_config, Notifier(room=self.room(username)))
            self._queues[username] = queue
            await queue.initialize()
            return queue

    def get_if_present(self, username):
        return self._queues.get(username)

    async def remove(self, username):
        async with self._lock:
            self._queues.pop(username, None)


dqueue = DownloadQueue(config, Notifier()) if not config.ENABLE_AUTH else None
user_queues = UserQueueRegistry(config) if config.ENABLE_AUTH else None


async def initialize_download_queues():
    if config.ENABLE_AUTH:
        if user_store is None:
            return
        for user in user_store.list_users():
            await user_queues.get(user['username'])
    elif dqueue is not None:
        await dqueue.initialize()


app.on_startup.append(lambda app: initialize_download_queues())


def request_user(request):
    return request.get('auth_user')


def require_authenticated_user(request):
    user = request_user(request)
    if config.ENABLE_AUTH and user is None:
        raise web.HTTPUnauthorized()
    return user


def require_admin(request):
    user = require_authenticated_user(request)
    if user is None or user.get('role') != 'admin':
        raise web.HTTPForbidden()
    return user


async def queue_for_request(request):
    if config.ENABLE_AUTH:
        user = require_authenticated_user(request)
        return await user_queues.get(user['username'])
    return dqueue


def safe_file_response(base_directory, relative_path):
    base_path = pathlib.Path(base_directory).resolve()
    decoded_path = unquote(relative_path)
    candidate = (base_path / decoded_path).resolve()
    try:
        candidate.relative_to(base_path)
    except ValueError as exc:
        raise web.HTTPForbidden() from exc
    if not candidate.is_file():
        raise web.HTTPNotFound()
    return web.FileResponse(candidate)


def parse_boolean_query(value, name):
    normalized = str(value).strip().lower()
    if normalized in ('1', 'true', 'yes', 'on'):
        return True
    if normalized in ('0', 'false', 'no', 'off'):
        return False
    raise ValueError(f'Query parameter "{name}" must be true/false.')


def queue_has_active_or_pending_items(queue):
    return (not queue.queue.empty()) or (not queue.pending.empty())


def public_user_from_session_user(session_user):
    return {
        'username': session_user['username'],
        'role': session_user['role'],
    }


async def invalidate_user_sessions(username):
    if not config.ENABLE_AUTH or user_queues is None:
        return

    room = user_queues.room(username)
    payload = serializer.encode({'username': username})
    await sio.emit('session_invalidated', payload, to=room)

class FileOpsFilter(DefaultFilter):
    def __call__(self, change_type: int, path: str) -> bool:
        # Check if this path matches our YTDL_OPTIONS_FILE
        if path != config.YTDL_OPTIONS_FILE:
            return False

        # For existing files, use samefile comparison to handle symlinks correctly
        if os.path.exists(config.YTDL_OPTIONS_FILE):
            try:
                if not os.path.samefile(path, config.YTDL_OPTIONS_FILE):
                    return False
            except (OSError, IOError):
                # If samefile fails, fall back to string comparison
                if path != config.YTDL_OPTIONS_FILE:
                    return False

        # Accept all change types for our file: modified, added, deleted
        return change_type in (Change.modified, Change.added, Change.deleted)

def get_options_update_time(success=True, msg=''):
    result = {
        'success': success,
        'msg': msg,
        'update_time': None
    }

    # Only try to get file modification time if YTDL_OPTIONS_FILE is set and file exists
    if config.YTDL_OPTIONS_FILE and os.path.exists(config.YTDL_OPTIONS_FILE):
        try:
            result['update_time'] = os.path.getmtime(config.YTDL_OPTIONS_FILE)
        except (OSError, IOError) as e:
            log.warning(f"Could not get modification time for {config.YTDL_OPTIONS_FILE}: {e}")
            result['update_time'] = None

    return result

async def watch_files():
    async def _watch_files():
        async for changes in awatch(config.YTDL_OPTIONS_FILE, watch_filter=FileOpsFilter()):
            success, msg = config.load_ytdl_options()
            result = get_options_update_time(success, msg)
            await sio.emit('ytdl_options_changed', serializer.encode(result))

    log.info(f'Starting Watch File: {config.YTDL_OPTIONS_FILE}')
    asyncio.create_task(_watch_files())

if config.YTDL_OPTIONS_FILE:
    app.on_startup.append(lambda app: watch_files())

@routes.get(config.URL_PREFIX + 'auth/me')
async def auth_me(request):
    user = request_user(request)
    return web.json_response({
        'enabled': config.ENABLE_AUTH,
        'authenticated': (not config.ENABLE_AUTH) or user is not None,
        'user': user,
    })


@routes.post(config.URL_PREFIX + 'auth/login')
async def auth_login(request):
    if not config.ENABLE_AUTH:
        return web.json_response({'status': 'ok', 'enabled': False})

    try:
        post = await request.json()
    except Exception as exc:
        raise web.HTTPBadRequest() from exc

    username = str(post.get('username', '')).strip()
    password = str(post.get('password', ''))
    session_user = user_store.verify_credentials_session(username, password) if user_store is not None else None
    if session_user is None:
        return web.json_response(
            {'status': 'error', 'msg': 'Invalid username or password.'},
            status=401,
        )

    response_user = public_user_from_session_user(session_user)
    response = web.json_response({'status': 'ok', 'user': response_user})
    session_manager.set_cookie(response, session_user)
    return response


@routes.post(config.URL_PREFIX + 'auth/logout')
async def auth_logout(request):
    response = web.json_response({'status': 'ok'})
    if config.ENABLE_AUTH and session_manager is not None:
        session_manager.clear_cookie(response)
    return response


@routes.get(config.URL_PREFIX + 'auth/users')
async def auth_users(request):
    if not config.ENABLE_AUTH:
        raise web.HTTPNotFound()
    require_admin(request)
    return web.json_response({'users': user_store.list_users()})


@routes.post(config.URL_PREFIX + 'auth/users')
async def auth_users_create(request):
    if not config.ENABLE_AUTH:
        raise web.HTTPNotFound()
    require_admin(request)

    try:
        post = await request.json()
    except Exception as exc:
        raise web.HTTPBadRequest() from exc

    username = str(post.get('username', '')).strip()
    password = str(post.get('password', ''))
    role = str(post.get('role', 'user')).strip().lower()

    try:
        user = user_store.create_user(username, password, role)
    except ValueError as exc:
        return web.json_response({'status': 'error', 'msg': str(exc)}, status=400)

    return web.json_response({'status': 'ok', 'user': user}, status=201)


@routes.delete(config.URL_PREFIX + 'auth/users/{username}')
async def auth_users_delete(request):
    if not config.ENABLE_AUTH:
        raise web.HTTPNotFound()
    admin_user = require_admin(request)

    username = str(request.match_info.get('username', '')).strip()
    if not username:
        raise web.HTTPBadRequest(text='username is required')
    if username == admin_user.get('username'):
        return web.json_response(
            {'status': 'error', 'msg': 'You cannot delete the currently logged-in account.'},
            status=400,
        )

    delete_downloads_raw = request.query.get('delete_downloads', 'false')
    try:
        delete_downloads = parse_boolean_query(delete_downloads_raw, 'delete_downloads')
    except ValueError as exc:
        return web.json_response({'status': 'error', 'msg': str(exc)}, status=400)

    existing_queue = user_queues.get_if_present(username) if user_queues is not None else None
    if existing_queue is not None and queue_has_active_or_pending_items(existing_queue):
        return web.json_response(
            {
                'status': 'error',
                'msg': f"User '{username}' has active or pending downloads. Cancel or finish them before deletion.",
            },
            status=409,
        )

    try:
        deleted_user = user_store.delete_user(username)
    except KeyError as exc:
        return web.json_response({'status': 'error', 'msg': str(exc)}, status=404)
    except ValueError as exc:
        return web.json_response({'status': 'error', 'msg': str(exc)}, status=400)

    await invalidate_user_sessions(username)

    if user_queues is not None:
        await user_queues.remove(username)
        paths = user_queues.user_paths(username)
    else:
        paths = {
            'download_dir': '',
            'audio_download_dir': '',
            'temp_dir': '',
            'state_dir': '',
        }

    if paths['state_dir']:
        shutil.rmtree(paths['state_dir'], ignore_errors=True)

    if delete_downloads:
        for directory in set((paths['download_dir'], paths['audio_download_dir'], paths['temp_dir'])):
            if directory:
                shutil.rmtree(directory, ignore_errors=True)

    return web.json_response(
        {
            'status': 'ok',
            'user': deleted_user,
            'deleted_downloads': delete_downloads,
        }
    )


@routes.post(config.URL_PREFIX + 'auth/users/{username}/password')
async def auth_users_change_password(request):
    if not config.ENABLE_AUTH:
        raise web.HTTPNotFound()

    actor = require_authenticated_user(request)
    username = str(request.match_info.get('username', '')).strip()
    if not username:
        raise web.HTTPBadRequest(text='username is required')

    try:
        post = await request.json()
    except Exception as exc:
        raise web.HTTPBadRequest() from exc

    new_password = str(post.get('new_password', ''))
    current_password = str(post.get('current_password', ''))

    is_admin = actor.get('role') == 'admin'
    is_self = actor.get('username') == username
    if (not is_admin) and (not is_self):
        raise web.HTTPForbidden()

    if (not is_admin) and is_self:
        if not current_password:
            return web.json_response(
                {'status': 'error', 'msg': 'Current password is required.'},
                status=400,
            )
        if not user_store.verify_user_password(username, current_password):
            return web.json_response(
                {'status': 'error', 'msg': 'Current password is incorrect.'},
                status=401,
            )

    try:
        updated_user = user_store.set_password(username, new_password)
    except ValueError as exc:
        return web.json_response({'status': 'error', 'msg': str(exc)}, status=400)
    except KeyError as exc:
        return web.json_response({'status': 'error', 'msg': str(exc)}, status=404)

    await invalidate_user_sessions(username)

    response = web.json_response(
        {
            'status': 'ok',
            'user': updated_user,
            'force_relogin': actor.get('username') == username,
        }
    )
    if actor.get('username') == username and session_manager is not None:
        session_manager.clear_cookie(response)
    return response


@routes.post(config.URL_PREFIX + 'add')
async def add(request):
    log.info("Received request to add download")
    post = await request.json()
    log.info(f"Request data: {post}")
    queue = await queue_for_request(request)
    url = post.get('url')
    quality = post.get('quality')
    if not url or not quality:
        log.error("Bad request: missing 'url' or 'quality'")
        raise web.HTTPBadRequest()
    format = post.get('format')
    folder = post.get('folder')
    custom_name_prefix = post.get('custom_name_prefix')
    playlist_item_limit = post.get('playlist_item_limit')
    auto_start = post.get('auto_start')
    split_by_chapters = post.get('split_by_chapters')
    chapter_template = post.get('chapter_template')

    if custom_name_prefix is None:
        custom_name_prefix = ''
    if auto_start is None:
        auto_start = True
    if playlist_item_limit is None:
        playlist_item_limit = queue.config.DEFAULT_OPTION_PLAYLIST_ITEM_LIMIT
    if split_by_chapters is None:
        split_by_chapters = False
    if chapter_template is None:
        chapter_template = queue.config.OUTPUT_TEMPLATE_CHAPTER

    playlist_item_limit = int(playlist_item_limit)

    status = await queue.add(url, quality, format, folder, custom_name_prefix, playlist_item_limit, auto_start, split_by_chapters, chapter_template)
    return web.Response(text=serializer.encode(status))

@routes.post(config.URL_PREFIX + 'delete')
async def delete(request):
    queue = await queue_for_request(request)
    post = await request.json()
    ids = post.get('ids')
    where = post.get('where')
    if not ids or where not in ['queue', 'done']:
        log.error("Bad request: missing 'ids' or incorrect 'where' value")
        raise web.HTTPBadRequest()
    status = await (queue.cancel(ids) if where == 'queue' else queue.clear(ids))
    log.info(f"Download delete request processed for ids: {ids}, where: {where}")
    return web.Response(text=serializer.encode(status))

@routes.post(config.URL_PREFIX + 'start')
async def start(request):
    queue = await queue_for_request(request)
    post = await request.json()
    ids = post.get('ids')
    log.info(f"Received request to start pending downloads for ids: {ids}")
    status = await queue.start_pending(ids)
    return web.Response(text=serializer.encode(status))

@routes.get(config.URL_PREFIX + 'history')
async def history(request):
    queue = await queue_for_request(request)
    history = { 'done': [], 'queue': [], 'pending': []}

    for _, v in queue.queue.saved_items():
        history['queue'].append(v)
    for _, v in queue.done.saved_items():
        history['done'].append(v)
    for _, v in queue.pending.saved_items():
        history['pending'].append(v)

    log.info("Sending download history")
    return web.Response(text=serializer.encode(history))

@sio.event
async def connect(sid, environ):
    queue = dqueue
    user = None

    if config.ENABLE_AUTH:
        session_user = session_manager.user_from_environ(environ) if session_manager is not None else None
        if session_user is not None and user_store is not None:
            persisted_user = user_store.get_session_user(session_user['username'])
            if (
                persisted_user is not None
                and persisted_user.get('session_version') == session_user.get('session_version')
            ):
                user = public_user_from_session_user(persisted_user)
        if user is None:
            log.warning("Rejected unauthenticated socket connection: %s", sid)
            return False
        queue = await user_queues.get(user['username'])
        await sio.enter_room(sid, user_queues.room(user['username']))
        log.info("Client connected: %s (%s)", sid, user['username'])
    else:
        log.info("Client connected: %s", sid)

    await sio.emit('all', serializer.encode(queue.get()), to=sid)
    await sio.emit('configuration', serializer.encode(get_client_config(user)), to=sid)
    if queue.config.CUSTOM_DIRS:
        await sio.emit('custom_dirs', serializer.encode(get_custom_dirs(queue.config)), to=sid)
    if config.YTDL_OPTIONS_FILE:
        await sio.emit('ytdl_options_changed', serializer.encode(get_options_update_time()), to=sid)

def get_custom_dirs(target_config):
    def recursive_dirs(base):
        path = pathlib.Path(base)

        # Converts path object to a relative string from base.
        def convert(p):
            try:
                rel = p.relative_to(path).as_posix()
                return '' if rel == '.' else rel
            except ValueError:
                return ''

        # Include only directories which do not match the exclude filter
        def include_dir(d):
            if len(target_config.CUSTOM_DIRS_EXCLUDE_REGEX) == 0:
                return True
            else:
                return re.search(target_config.CUSTOM_DIRS_EXCLUDE_REGEX, d) is None

        # Recursively lists all subdirectories of DOWNLOAD_DIR
        dirs = list(filter(include_dir, map(convert, path.glob('**/'))))

        return dirs

    download_dir = recursive_dirs(target_config.DOWNLOAD_DIR)

    audio_download_dir = download_dir
    if target_config.DOWNLOAD_DIR != target_config.AUDIO_DOWNLOAD_DIR:
        audio_download_dir = recursive_dirs(target_config.AUDIO_DOWNLOAD_DIR)

    return {
        "download_dir": download_dir,
        "audio_download_dir": audio_download_dir
    }

@routes.get(config.URL_PREFIX)
def index(request):
    response = web.FileResponse(os.path.join(config.BASE_DIR, 'ui/dist/metube/browser/index.html'))
    if 'metube_theme' not in request.cookies:
        response.set_cookie('metube_theme', config.DEFAULT_THEME)
    return response

@routes.get(config.URL_PREFIX + 'robots.txt')
def robots(request):
    if config.ROBOTS_TXT:
        response = web.FileResponse(os.path.join(config.BASE_DIR, config.ROBOTS_TXT))
    else:
        response = web.Response(
            text="User-agent: *\nDisallow: /download/\nDisallow: /audio_download/\n"
        )
    return response

@routes.get(config.URL_PREFIX + 'version')
def version(request):
    return web.json_response({
        "yt-dlp": yt_dlp_version,
        "version": os.getenv("METUBE_VERSION", "dev")
    })

if config.URL_PREFIX != '/':
    @routes.get('/')
    def index_redirect_root(request):
        return web.HTTPFound(config.URL_PREFIX)

    @routes.get(config.URL_PREFIX[:-1])
    def index_redirect_dir(request):
        return web.HTTPFound(config.URL_PREFIX)

if config.ENABLE_AUTH:
    @routes.get(config.URL_PREFIX + 'download/{path:.*}')
    async def download_file(request):
        user = require_authenticated_user(request)
        queue = await user_queues.get(user['username'])
        return safe_file_response(queue.config.DOWNLOAD_DIR, request.match_info.get('path', ''))

    @routes.get(config.URL_PREFIX + 'audio_download/{path:.*}')
    async def audio_download_file(request):
        user = require_authenticated_user(request)
        queue = await user_queues.get(user['username'])
        return safe_file_response(queue.config.AUDIO_DOWNLOAD_DIR, request.match_info.get('path', ''))
else:
    routes.static(config.URL_PREFIX + 'download/', config.DOWNLOAD_DIR, show_index=config.DOWNLOAD_DIRS_INDEXABLE)
    routes.static(config.URL_PREFIX + 'audio_download/', config.AUDIO_DOWNLOAD_DIR, show_index=config.DOWNLOAD_DIRS_INDEXABLE)

routes.static(config.URL_PREFIX, os.path.join(config.BASE_DIR, 'ui/dist/metube/browser'))
try:
    app.add_routes(routes)
except ValueError as e:
    if 'ui/dist/metube/browser' in str(e):
        raise RuntimeError('Could not find the frontend UI static assets. Please run `node_modules/.bin/ng build` inside the ui folder') from e
    raise e

# https://github.com/aio-libs/aiohttp/pull/4615 waiting for release
# @routes.options(config.URL_PREFIX + 'add')
async def add_cors(request):
    return web.Response(text=serializer.encode({"status": "ok"}))

app.router.add_route('OPTIONS', config.URL_PREFIX + 'add', add_cors)

async def on_prepare(request, response):
    if 'Origin' in request.headers:
        response.headers['Access-Control-Allow-Origin'] = request.headers['Origin']
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type'

app.on_response_prepare.append(on_prepare)

def supports_reuse_port():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        sock.close()
        return True
    except (AttributeError, OSError):
        return False

def isAccessLogEnabled():
    if config.ENABLE_ACCESSLOG:
        return access_logger
    else:
        return None

if __name__ == '__main__':
    logging.getLogger().setLevel(parseLogLevel(config.LOGLEVEL) or logging.INFO)
    log.info(f"Listening on {config.HOST}:{config.PORT}")

    if config.HTTPS:
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain(certfile=config.CERTFILE, keyfile=config.KEYFILE)
        web.run_app(app, host=config.HOST, port=int(config.PORT), reuse_port=supports_reuse_port(), ssl_context=ssl_context, access_log=isAccessLogEnabled())
    else:
        web.run_app(app, host=config.HOST, port=int(config.PORT), reuse_port=supports_reuse_port(), access_log=isAccessLogEnabled())
