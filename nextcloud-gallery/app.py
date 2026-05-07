"""
Photo Gallery — Google-Photos-style UI
Home SOC Lab · Flask app on port 5001

Features
--------
- Left sidebar with VS Code-style directory tree of the local media folder
- Photos / Videos filter pills
- Main feed sorted by date (EXIF where available, mtime fallback), grouped by day
- "Memories" row: on-this-day photos from 1y / 2y / 3y ago
- Nextcloud WebDAV browsing preserved at /nextcloud
- Full-image thumbnail endpoint with on-disk cache (resized via Pillow if installed)
- Range-request aware media streaming so videos start quickly
"""

from flask import (
    Flask, request, session, redirect, url_for,
    render_template_string, Response, jsonify, send_from_directory, abort
)
import requests
from requests.auth import HTTPBasicAuth
import xml.etree.ElementTree as ET
import urllib.parse
import urllib3
import socket
import os
import io
import re
import json
import time
import mimetypes
import hashlib
import threading
import subprocess
import shutil
from datetime import datetime, date, timedelta

# Optional: Pillow for thumbnail resizing + EXIF date parsing. Falls back gracefully.
try:
    from PIL import Image, ExifTags
    HAVE_PIL = True
except ImportError:
    HAVE_PIL = False

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
app.secret_key = os.environ.get('GALLERY_SECRET', 'homelab-gallery-secret-2026')


# =============================================================================
# Config
# =============================================================================
def get_nextcloud_url():
    for ip in ["192.168.2.15", "10.0.0.108"]:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.settimeout(1)
            s.connect((ip, 80))
            return f"http://{ip}"
        except Exception:
            pass
        finally:
            s.close()
    return "http://10.0.0.108"


NEXTCLOUD_URL = get_nextcloud_url()
NEXTCLOUD_USER = os.environ.get('NEXTCLOUD_USER', 'admin')
NEXTCLOUD_PASS = os.environ.get('NEXTCLOUD_PASS', 'Ihatethor4@')
WEBDAV_BASE = f'{NEXTCLOUD_URL}/remote.php/dav/files/{NEXTCLOUD_USER}'
GALLERY_PASSWORD = os.environ.get('GALLERY_PASSWORD', 'gallery123')

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MEDIA_DIR = os.path.join(BASE_DIR, 'media')
THUMB_CACHE = os.path.join(BASE_DIR, '.thumb_cache')
METADATA_FILE = os.path.join(BASE_DIR, '.metadata_cache.json')
os.makedirs(MEDIA_DIR, exist_ok=True)
os.makedirs(THUMB_CACHE, exist_ok=True)

IMAGE_EXTS = ('.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp', '.heic')
VIDEO_EXTS = ('.mp4', '.webm', '.ogg', '.mov', '.mkv', '.avi')

# Thumbnail target (smaller = faster decode + less bandwidth)
THUMB_SIZE = 220
FEED_TTL = 30  # seconds — in-memory feed cache lifetime

# ffmpeg for video poster frames. Optional — falls back to gradient tile if missing.
FFMPEG_BIN = shutil.which('ffmpeg')
HAVE_FFMPEG = FFMPEG_BIN is not None

auth = HTTPBasicAuth(NEXTCLOUD_USER, NEXTCLOUD_PASS)

# =============================================================================
# Caches (persistent metadata + in-memory feed)
# =============================================================================
_metadata = {}               # path -> {mtime, size, dt_iso, is_image, is_video}
_metadata_lock = threading.Lock()
_metadata_dirty = False

_feed_cache = {}             # (scope, kind) -> (expiry_ts, result)
_feed_lock = threading.Lock()

_warmer_started = False
_warmer_lock = threading.Lock()


def load_metadata_cache():
    global _metadata
    try:
        with open(METADATA_FILE, 'r') as f:
            _metadata = json.load(f)
    except (OSError, json.JSONDecodeError):
        _metadata = {}


def save_metadata_cache():
    global _metadata_dirty
    with _metadata_lock:
        if not _metadata_dirty:
            return
        try:
            tmp = METADATA_FILE + '.tmp'
            with open(tmp, 'w') as f:
                json.dump(_metadata, f)
            os.replace(tmp, METADATA_FILE)
            _metadata_dirty = False
        except OSError:
            pass


def invalidate_feed_cache():
    with _feed_lock:
        _feed_cache.clear()


load_metadata_cache()


# =============================================================================
# Helpers
# =============================================================================
def is_image(name): return name.lower().endswith(IMAGE_EXTS)
def is_video(name): return name.lower().endswith(VIDEO_EXTS)
def is_media(name): return is_image(name) or is_video(name)


def human_size(b):
    for unit in ['B', 'KB', 'MB', 'GB']:
        if b < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} TB"


def safe_join(base, rel):
    """Prevent path traversal. Returns absolute path only if it stays under base."""
    rel = (rel or '').lstrip('/\\')
    full = os.path.normpath(os.path.join(base, rel))
    if os.path.commonpath([os.path.abspath(full), os.path.abspath(base)]) != os.path.abspath(base):
        return None
    return full


def exif_datetime(path):
    """Return datetime from EXIF if available, else None."""
    if not HAVE_PIL:
        return None
    try:
        img = Image.open(path)
        exif = img._getexif() or {}
        for tag_id, value in exif.items():
            tag = ExifTags.TAGS.get(tag_id)
            if tag in ('DateTimeOriginal', 'DateTime', 'DateTimeDigitized'):
                return datetime.strptime(value, '%Y:%m:%d %H:%M:%S')
    except Exception:
        return None
    return None


def file_datetime(path):
    """Best-effort timestamp: EXIF first, then mtime. Not cached (see cached_meta)."""
    if is_image(path):
        dt = exif_datetime(path)
        if dt:
            return dt
    try:
        return datetime.fromtimestamp(os.path.getmtime(path))
    except Exception:
        return datetime.fromtimestamp(0)


def cached_meta(abs_path, rel_path):
    """
    Return {mtime, size, dt_iso, is_image, is_video} for a file, using the
    persistent cache when the mtime hasn't changed. This is the key perf win:
    EXIF parsing only happens once per file per mtime.
    """
    global _metadata_dirty
    try:
        st = os.stat(abs_path)
    except OSError:
        return None
    mtime = int(st.st_mtime)
    size = st.st_size
    key = rel_path.replace('\\', '/')
    cached = _metadata.get(key)
    if cached and cached.get('mtime') == mtime and cached.get('size') == size:
        return cached
    # Miss — compute fresh
    img, vid = is_image(key), is_video(key)
    dt = file_datetime(abs_path)
    entry = {
        'mtime': mtime,
        'size': size,
        'dt_iso': dt.isoformat(),
        'is_image': img,
        'is_video': vid,
    }
    with _metadata_lock:
        _metadata[key] = entry
        _metadata_dirty = True
    return entry


def walk_tree(base=MEDIA_DIR, rel=''):
    """Recursive folder tree for the sidebar. Returns nested dicts with counts."""
    abs_path = os.path.join(base, rel) if rel else base
    if not os.path.isdir(abs_path):
        return None
    children = []
    file_count = 0
    try:
        entries = sorted(os.listdir(abs_path), key=str.lower)
    except OSError:
        entries = []
    for name in entries:
        if name.startswith('.'):
            continue
        full = os.path.join(abs_path, name)
        child_rel = os.path.join(rel, name) if rel else name
        if os.path.isdir(full):
            sub = walk_tree(base, child_rel)
            if sub:
                children.append(sub)
                file_count += sub['count']
        elif os.path.isfile(full) and is_media(name):
            file_count += 1
    return {
        'name': os.path.basename(abs_path) if rel else 'media',
        'path': rel.replace('\\', '/'),
        'count': file_count,
        'children': children,
    }


def scan_media(scope='', kind='all'):
    """
    Walk MEDIA_DIR (optionally limited to a sub-path) and return a list of files
    with full metadata. `kind` ∈ {'all','photos','videos'}.
    Uses the persistent metadata cache to skip EXIF parsing for unchanged files.
    """
    root = safe_join(MEDIA_DIR, scope) if scope else MEDIA_DIR
    if not root or not os.path.isdir(root):
        return []
    results = []
    touched = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if not d.startswith('.')]
        for name in filenames:
            if name.startswith('.'):
                continue
            img, vid = is_image(name), is_video(name)
            if kind == 'photos' and not img:
                continue
            if kind == 'videos' and not vid:
                continue
            if not (img or vid):
                continue
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, MEDIA_DIR).replace('\\', '/')
            meta = cached_meta(full, rel)
            if meta is None:
                continue
            touched += 1
            dt_iso = meta['dt_iso']
            # Only format the display strings at request time — these aren't cached
            try:
                dt = datetime.fromisoformat(dt_iso)
            except ValueError:
                dt = datetime.fromtimestamp(meta.get('mtime', 0))
            results.append({
                'name': name,
                'path': rel,
                'dir': os.path.dirname(rel),
                'size': meta['size'],
                'size_h': human_size(meta['size']),
                'is_image': img,
                'is_video': vid,
                'dt_iso': dt_iso,
                'dt_key': dt.strftime('%Y-%m-%d'),
                'dt_label': dt.strftime('%A, %b %d, %Y'),
            })
    results.sort(key=lambda r: r['dt_iso'], reverse=True)
    if touched:
        save_metadata_cache()
    return results


def cached_feed(scope='', kind='all'):
    """30s in-memory cache shared across /api/feed and /api/memories."""
    key = (scope, kind)
    now = time.time()
    with _feed_lock:
        if key in _feed_cache:
            expiry, data = _feed_cache[key]
            if expiry > now:
                return data
    items = scan_media(scope=scope, kind=kind)
    groups = group_by_day(items)
    totals = {
        'photos': sum(1 for i in items if i['is_image']),
        'videos': sum(1 for i in items if i['is_video']),
        'total': len(items),
    }
    data = {'groups': groups, 'totals': totals, '_items': items}
    with _feed_lock:
        _feed_cache[key] = (now + FEED_TTL, data)
    return data


def group_by_day(items):
    """Group a sorted list into day-buckets for the main feed."""
    groups = []
    current = None
    for it in items:
        if current is None or current['key'] != it['dt_key']:
            current = {
                'key': it['dt_key'],
                'label': it['dt_label'],
                'photos': 0,
                'videos': 0,
                'items': [],
            }
            groups.append(current)
        current['items'].append(it)
        if it['is_image']:
            current['photos'] += 1
        else:
            current['videos'] += 1
    return groups


def build_memories(items, today=None):
    """On-this-day memories: photos from N years ago, same month/day (±3 days)."""
    today = today or date.today()
    memories = []
    for years_ago in (1, 2, 3, 4, 5):
        target = date(today.year - years_ago, today.month, min(today.day, 28))
        window_start = target - timedelta(days=3)
        window_end = target + timedelta(days=3)
        hits = [i for i in items
                if window_start <= datetime.fromisoformat(i['dt_iso']).date() <= window_end]
        if hits:
            memories.append({
                'label': f"{years_ago} year{'s' if years_ago > 1 else ''} ago",
                'cover': hits[0]['path'],
                'count': len(hits),
                'date_key': target.isoformat(),
            })
    recent = [i for i in items
              if datetime.fromisoformat(i['dt_iso']).date() >= today - timedelta(days=7)]
    if recent:
        memories.insert(0, {
            'label': 'Recently added',
            'cover': recent[0]['path'],
            'count': len(recent),
            'date_key': '',
        })
    return memories


# =============================================================================
# Nextcloud WebDAV (preserved)
# =============================================================================
def webdav_list(path='/'):
    url = WEBDAV_BASE + path
    try:
        r = requests.request('PROPFIND', url, auth=auth, headers={'Depth': '1'},
                             verify=False, timeout=10)
    except requests.RequestException:
        return []
    if r.status_code not in (207, 200):
        return []
    try:
        root = ET.fromstring(r.text)
    except ET.ParseError:
        return []
    ns = {'d': 'DAV:'}
    items = []
    for resp in root.findall('d:response', ns):
        href = resp.find('d:href', ns).text or ''
        props = resp.find('.//d:prop', ns)
        is_collection = props.find('d:resourcetype/d:collection', ns) is not None
        last_modified = props.find('d:getlastmodified', ns)
        size = props.find('d:getcontentlength', ns)
        name = urllib.parse.unquote(href.rstrip('/').split('/')[-1])
        if not name or href.endswith(f'/files/{NEXTCLOUD_USER}/') or href.endswith(f'/files/{NEXTCLOUD_USER}'):
            continue
        items.append({
            'name': name,
            'href': href,
            'is_dir': is_collection,
            'modified': last_modified.text if last_modified is not None else '',
            'size': int(size.text) if size is not None and size.text else 0,
            'path': path.rstrip('/') + '/' + name,
        })
    items.sort(key=lambda x: x['modified'], reverse=True)
    return items


# =============================================================================
# Auth gate
# =============================================================================
def require_auth():
    if not session.get('auth'):
        return redirect(url_for('login'))
    return None


# =============================================================================
# Routes — auth
# =============================================================================
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = ''
    if request.method == 'POST':
        if request.form.get('password') == GALLERY_PASSWORD:
            session['auth'] = True
            return redirect(url_for('gallery'))
        error = 'Wrong password'
    return render_template_string(LOGIN_HTML, error=error)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


# =============================================================================
# Routes — main UI
# =============================================================================
@app.route('/')
def gallery():
    r = require_auth()
    if r: return r
    return render_template_string(GALLERY_HTML)


@app.route('/nextcloud')
def nextcloud():
    r = require_auth()
    if r: return r
    path = request.args.get('path', '/')
    search = request.args.get('search', '').lower()
    items = webdav_list(path)
    if search:
        items = [i for i in items if search in i['name'].lower()]
    folders = [i for i in items if i['is_dir']]
    photos = [i for i in items if not i['is_dir'] and is_image(i['name'])]
    files = [i for i in items if not i['is_dir'] and not is_image(i['name'])]
    parts = [p for p in path.split('/') if p]
    breadcrumbs = [('Home', '/')]
    current = ''
    for p in parts:
        current += '/' + p
        breadcrumbs.append((p, current))
    return render_template_string(NEXTCLOUD_HTML,
        path=path, folders=folders, photos=photos, files=files,
        breadcrumbs=breadcrumbs, search=search,
        human_size=human_size)


# =============================================================================
# Routes — JSON API for the new UI
# =============================================================================
@app.route('/api/tree')
def api_tree():
    r = require_auth()
    if r: return '', 403
    return jsonify(walk_tree() or {'name': 'media', 'path': '', 'count': 0, 'children': []})


@app.route('/api/feed')
def api_feed():
    r = require_auth()
    if r: return '', 403
    scope = request.args.get('path', '')
    kind = request.args.get('type', 'all')  # all | photos | videos
    data = cached_feed(scope=scope, kind=kind)
    start_thumb_warmer()
    # Don't ship the raw _items list — frontend only needs groups + totals
    return jsonify({'groups': data['groups'], 'totals': data['totals']})


@app.route('/api/memories')
def api_memories():
    r = require_auth()
    if r: return '', 403
    data = cached_feed(scope='', kind='all')
    return jsonify(build_memories(data['_items']))


# =============================================================================
# Routes — media serving
# =============================================================================
@app.route('/media/<path:filename>')
def serve_media(filename):
    r = require_auth()
    if r: return '', 403
    full = safe_join(MEDIA_DIR, filename)
    if not full or not os.path.isfile(full):
        abort(404)
    mimetype, _ = mimetypes.guess_type(filename)
    return send_from_directory(MEDIA_DIR, filename, mimetype=mimetype, conditional=True)


def _thumb_cache_path(rel_path, mtime):
    """Deterministic cache path from (rel_path, mtime) — same scheme used by /thumb and the warmer."""
    cache_key = hashlib.md5(f"{rel_path}:{mtime}".encode()).hexdigest()
    return os.path.join(THUMB_CACHE, cache_key + '.jpg')


def _ensure_cache_dir():
    try:
        os.makedirs(THUMB_CACHE, exist_ok=True)
    except OSError:
        pass


def _make_thumb(full, cache_path):
    """Generate a thumbnail; returns True on success, False on failure."""
    _ensure_cache_dir()
    try:
        img = Image.open(full)
        img = _apply_exif_rotation(img)
        img.thumbnail((THUMB_SIZE, THUMB_SIZE))
        if img.mode in ('RGBA', 'P', 'LA'):
            img = img.convert('RGB')
        img.save(cache_path, 'JPEG', quality=82, optimize=True)
        return True
    except Exception:
        return False


def _make_video_poster(full, cache_path):
    """
    Extract a poster-frame JPEG from a video via ffmpeg. Grabs a frame ~1s in
    (falls back to 0s for short clips), scales to THUMB_SIZE max dimension.
    Returns True on success.
    """
    if not HAVE_FFMPEG:
        return False
    _ensure_cache_dir()
    scale_filter = f"scale='min({THUMB_SIZE},iw)':'min({THUMB_SIZE},ih)':force_original_aspect_ratio=decrease"
    for seek in ('00:00:01', '00:00:00'):
        try:
            proc = subprocess.run(
                [FFMPEG_BIN, '-y', '-loglevel', 'error',
                 '-ss', seek, '-i', full,
                 '-frames:v', '1', '-vf', scale_filter, '-q:v', '4',
                 cache_path],
                timeout=10, capture_output=True,
            )
            if proc.returncode == 0 and os.path.exists(cache_path) and os.path.getsize(cache_path) > 0:
                return True
        except (subprocess.TimeoutExpired, OSError):
            continue
    return False


@app.route('/thumb/<path:filename>')
def local_thumb(filename):
    """
    Resized local thumbnail with on-disk cache + browser cache headers.
    Handles both images (via Pillow) and videos (via ffmpeg poster frame).
    """
    r = require_auth()
    if r: return '', 403
    full = safe_join(MEDIA_DIR, filename)
    if not full or not os.path.isfile(full):
        abort(404)
    try:
        mtime = int(os.path.getmtime(full))
    except OSError:
        mtime = 0
    cache_path = _thumb_cache_path(filename, mtime)

    if is_image(filename):
        if not HAVE_PIL:
            return send_from_directory(MEDIA_DIR, filename)
        if not os.path.exists(cache_path):
            if not _make_thumb(full, cache_path):
                return send_from_directory(MEDIA_DIR, filename)
    elif is_video(filename):
        if not os.path.exists(cache_path):
            if not _make_video_poster(full, cache_path):
                abort(404)
    else:
        return send_from_directory(MEDIA_DIR, filename)

    resp = send_from_directory(THUMB_CACHE, os.path.basename(cache_path), mimetype='image/jpeg')
    # Safe to cache forever: cache key contains mtime, so stale files can't be served.
    resp.headers['Cache-Control'] = 'public, max-age=31536000, immutable'
    return resp


# =============================================================================
# Background thumbnail pre-warmer
# =============================================================================
def start_thumb_warmer():
    """Kick off a daemon thread that generates missing thumbnails in the background."""
    global _warmer_started
    if not HAVE_PIL:
        return
    with _warmer_lock:
        if _warmer_started:
            return
        _warmer_started = True
    threading.Thread(target=_warm_thumbs, daemon=True, name='thumb-warmer').start()


def _warm_thumbs():
    """Walk MEDIA_DIR and generate any missing thumbnails (images + video posters)."""
    try:
        for dirpath, dirnames, filenames in os.walk(MEDIA_DIR):
            dirnames[:] = [d for d in dirnames if not d.startswith('.')]
            for name in filenames:
                if name.startswith('.'):
                    continue
                img, vid = is_image(name), is_video(name)
                if not (img or vid):
                    continue
                full = os.path.join(dirpath, name)
                try:
                    mtime = int(os.path.getmtime(full))
                except OSError:
                    continue
                rel = os.path.relpath(full, MEDIA_DIR).replace('\\', '/')
                cache_path = _thumb_cache_path(rel, mtime)
                if os.path.exists(cache_path):
                    continue
                if img:
                    _make_thumb(full, cache_path)
                elif vid and HAVE_FFMPEG:
                    _make_video_poster(full, cache_path)
    except Exception:
        pass


def _apply_exif_rotation(img):
    try:
        exif = img._getexif() or {}
        orientation_tag = next(k for k, v in ExifTags.TAGS.items() if v == 'Orientation')
        o = exif.get(orientation_tag, 1)
        if o == 3: img = img.rotate(180, expand=True)
        elif o == 6: img = img.rotate(270, expand=True)
        elif o == 8: img = img.rotate(90, expand=True)
    except Exception:
        pass
    return img


@app.route('/nc-thumb')
def nc_thumb():
    """Proxy a Nextcloud image (full size — kept for Nextcloud view)."""
    r = require_auth()
    if r: return '', 403
    path = request.args.get('path', '')
    url = WEBDAV_BASE + path
    try:
        rr = requests.get(url, auth=auth, verify=False, stream=True, timeout=10)
    except requests.RequestException:
        abort(502)
    return Response(rr.content, mimetype=rr.headers.get('Content-Type', 'image/jpeg'))


@app.route('/download')
def download():
    r = require_auth()
    if r: return '', 403
    source = request.args.get('source', 'local')  # 'local' or 'nextcloud'
    path = request.args.get('path', '')
    if source == 'nextcloud':
        name = path.split('/')[-1]
        url = WEBDAV_BASE + path
        try:
            rr = requests.get(url, auth=auth, verify=False, stream=True, timeout=30)
        except requests.RequestException:
            abort(502)
        return Response(
            rr.iter_content(chunk_size=8192),
            mimetype='application/octet-stream',
            headers={'Content-Disposition': f'attachment; filename="{name}"'},
        )
    full = safe_join(MEDIA_DIR, path)
    if not full or not os.path.isfile(full):
        abort(404)
    return send_from_directory(MEDIA_DIR, path, as_attachment=True)


# =============================================================================
# Templates
# =============================================================================
LOGIN_HTML = r'''
<!DOCTYPE html>
<html><head>
  <title>Photo Gallery — Login</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { background: #0f0e17; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
           display: flex; align-items: center; justify-content: center; min-height: 100vh;
           color: #e0e0e0; padding: 20px; }
    .box { background: #14141f; border: 1px solid #7c6fe033; border-radius: 14px;
           padding: 36px 32px; width: 100%; max-width: 340px; }
    @media (max-width: 420px) {
      .box { padding: 28px 22px; }
      .logo { font-size: 26px; }
    }
    .logo { font-family: Georgia, serif; font-style: italic; font-size: 30px; font-weight: 700;
            color: #e0e0e0; margin-bottom: 4px; }
    .logo .dot { color: #7c6fe0; }
    .sub { color: #555; font-size: 11px; letter-spacing: 0.2em; text-transform: uppercase; margin-bottom: 28px; }
    input { width: 100%; background: #0f0e17; border: 1px solid #2a2a3a; border-radius: 8px;
            color: #e0e0e0; padding: 11px 14px; font-size: 14px; margin-bottom: 12px; font-family: inherit; }
    input:focus { outline: none; border-color: #7c6fe0; }
    button { width: 100%; background: #7c6fe0; color: #fff; border: none; border-radius: 8px;
             padding: 11px; font-size: 14px; cursor: pointer; letter-spacing: 0.05em; font-family: inherit; }
    button:hover { background: #6a5fc8; }
    .err { color: #ff4d6d; font-size: 12px; margin-bottom: 12px; }
  </style>
</head><body>
  <div class="box">
    <div class="logo">Photo<span class="dot">.</span></div>
    <div class="sub">Home SOC Lab · Private Access</div>
    {% if error %}<div class="err">{{ error }}</div>{% endif %}
    <form method="POST">
      <input type="password" name="password" placeholder="Password" autofocus>
      <button type="submit">ENTER</button>
    </form>
  </div>
</body></html>
'''

GALLERY_HTML = r'''
<!DOCTYPE html>
<html><head>
  <title>Photo Gallery</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    html, body { height: 100%; }
    body { background: #0f0e17; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
           color: #e0e0e0; overflow: hidden; }
    .shell { display: flex; height: 100vh; }
    .sidebar { width: 260px; min-width: 260px; background: #0a0a14; border-right: 1px solid #1e1e2e;
               display: flex; flex-direction: column; }
    .main { flex: 1; overflow: auto; }
    .logo-wrap { padding: 22px 20px 16px; border-bottom: 1px solid #1a1a28; }
    .logo { font-family: Georgia, serif; font-style: italic; font-weight: 700; color: #e0e0e0; font-size: 26px; }
    .logo .dot { color: #7c6fe0; }
    .logo-sub { color: #555; font-size: 10px; letter-spacing: 0.2em; margin-top: 4px; text-transform: uppercase; }

    .tree-section { padding: 14px 0 10px; border-bottom: 1px solid #1a1a28; flex: 1; overflow-y: auto; }
    .tree-title { color: #7c6fe0; font-size: 10px; letter-spacing: 0.15em; text-transform: uppercase;
                  padding: 0 20px 8px; font-weight: 600; }
    .tree ul { list-style: none; }
    .tree li { font-size: 13px; }
    .tree .node { display: flex; align-items: center; gap: 4px; padding: 3px 20px 3px 12px;
                  cursor: pointer; color: #c8c8d0; user-select: none; }
    .tree .node:hover { background: #1a1a28; }
    .tree .node.active { background: #7c6fe022; color: #7c6fe0; }
    .tree .chev { display: inline-block; width: 12px; font-size: 10px; color: #666; transition: transform 0.1s; }
    .tree li.expanded > .node > .chev { transform: rotate(90deg); }
    .tree .icon { width: 14px; font-size: 12px; }
    .tree .name { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .tree .count { margin-left: auto; color: #555; font-size: 10px; }
    .tree ul ul { padding-left: 18px; display: none; }
    .tree li.expanded > ul { display: block; }
    .tree .leaf .chev { visibility: hidden; }

    .filters { padding: 14px 16px 18px; border-top: 1px solid #1a1a28; }
    .filter-title { color: #555; font-size: 10px; letter-spacing: 0.15em; text-transform: uppercase; margin-bottom: 10px; }
    .filter-btn { display: flex; align-items: center; gap: 12px; width: 100%; padding: 10px 12px;
                  background: #14141f; border: 1px solid #1f1f30; border-radius: 8px;
                  color: #c8c8d0; font-size: 13px; cursor: pointer; margin-bottom: 8px;
                  transition: all 0.12s; font-family: inherit; }
    .filter-btn:hover { border-color: #7c6fe055; }
    .filter-btn.active { background: #7c6fe022; border-color: #7c6fe0; color: #7c6fe0; }
    .filter-btn .f-icon { font-size: 16px; }
    .filter-btn .f-count { margin-left: auto; color: #555; font-size: 11px; }
    .filter-btn.active .f-count { color: #7c6fe0aa; }

    .side-foot { padding: 12px 20px; border-top: 1px solid #1a1a28;
                 display: flex; align-items: center; justify-content: space-between;
                 font-size: 11px; color: #555; }
    .side-foot a { color: #7c6fe0; text-decoration: none; }
    .side-foot a:hover { color: #a094f0; }

    .topbar { position: sticky; top: 0; z-index: 20; background: #0f0e17ee; backdrop-filter: blur(8px);
              border-bottom: 1px solid #1a1a28; padding: 14px 28px; display: flex; align-items: center; gap: 16px; }
    .search { flex: 1; max-width: 640px; background: #14141f; border: 1px solid #1f1f30;
              border-radius: 24px; padding: 10px 18px; color: #e0e0e0; font-size: 14px; font-family: inherit; }
    .search:focus { outline: none; border-color: #7c6fe0; }
    .scope-tag { color: #7c6fe0; font-size: 11px; letter-spacing: 0.1em; padding: 6px 12px;
                 border: 1px solid #7c6fe055; border-radius: 20px; background: #7c6fe011; }
    .avatar { width: 32px; height: 32px; border-radius: 50%; background: linear-gradient(135deg, #7c6fe0, #4a3fa0);
              display: flex; align-items: center; justify-content: center; color: #fff; font-weight: 700;
              font-size: 13px; margin-left: auto; }

    .memories { padding: 20px 28px 10px; }
    .memories-row { display: flex; gap: 12px; overflow-x: auto; padding-bottom: 8px; }
    .memory { position: relative; min-width: 170px; width: 170px; height: 230px; border-radius: 14px;
              overflow: hidden; cursor: pointer; flex-shrink: 0; border: 1px solid #1f1f30; background: #14141f; }
    .memory img { width: 100%; height: 100%; object-fit: cover; display: block; }
    .memory::after { content: ''; position: absolute; inset: 0;
                     background: linear-gradient(180deg, transparent 40%, rgba(0,0,0,0.8) 100%); pointer-events: none; }
    .memory .m-label { position: absolute; bottom: 12px; left: 12px; right: 12px;
                       color: #fff; font-size: 14px; font-weight: 600; z-index: 1; line-height: 1.2; }
    .memory .m-count { position: absolute; top: 12px; right: 12px; background: rgba(0,0,0,0.55);
                       color: #fff; font-size: 11px; padding: 3px 8px; border-radius: 10px; z-index: 1; }

    .groups { padding: 10px 28px 40px; }
    .group { margin-bottom: 32px; }
    .group-head { display: flex; align-items: baseline; gap: 14px; margin-bottom: 10px; }
    .group-date { color: #e0e0e0; font-size: 16px; font-weight: 600; }
    .group-meta { color: #666; font-size: 12px; }
    .group-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: 4px; }
    .tile { position: relative; aspect-ratio: 1 / 1; overflow: hidden; border-radius: 2px;
            cursor: pointer; background: #1a1a28; transition: transform 0.12s; }
    .tile:hover { transform: scale(1.015); z-index: 2; box-shadow: 0 4px 20px rgba(0,0,0,0.6); }
    .tile img, .tile video { width: 100%; height: 100%; object-fit: cover; display: block; }
    .tile .vid-badge { position: absolute; top: 8px; right: 8px; background: rgba(0,0,0,0.6);
                       color: #fff; font-size: 10px; padding: 2px 6px; border-radius: 10px; }
    .tile-video-ph { width: 100%; height: 100%;
                     background: linear-gradient(135deg, #1a1a28, #2a2a3a);
                     display: flex; align-items: center; justify-content: center; }
    .tile-play { font-size: 28px; color: #7c6fe0aa; }
    /* Play-icon overlay centered on video poster tiles */
    .tile-play-overlay { position: absolute; top: 50%; left: 50%;
                         transform: translate(-50%, -50%);
                         width: 44px; height: 44px; border-radius: 50%;
                         background: rgba(0,0,0,0.55); color: #fff;
                         display: flex; align-items: center; justify-content: center;
                         font-size: 16px; pointer-events: none;
                         box-shadow: 0 2px 12px rgba(0,0,0,0.5); }
    .tile[data-kind="video"] .vid-badge { display: none; }
    /* Skeleton while feed loads */
    @keyframes shimmer { 0% { background-position: -400px 0; } 100% { background-position: 400px 0; } }
    .group-grid[data-shell="1"] { background: transparent; }

    .empty { text-align: center; color: #555; padding: 80px 0; font-size: 14px; }
    .loading { text-align: center; color: #7c6fe0; padding: 40px 0; font-size: 12px; letter-spacing: 0.1em; }

    /* Lightbox */
    .lb { display: none; position: fixed; inset: 0; background: rgba(0,0,0,0.95);
          z-index: 999; align-items: center; justify-content: center; }
    .lb.active { display: flex; }
    .lb img, .lb video { max-width: 92vw; max-height: 92vh; border-radius: 4px; }
    .lb-close { position: fixed; top: 20px; right: 28px; color: #fff; font-size: 32px;
                cursor: pointer; z-index: 1000; }
    .lb-meta { position: fixed; bottom: 20px; left: 50%; transform: translateX(-50%);
               color: #aaa; font-size: 12px; }

    ::-webkit-scrollbar { width: 8px; height: 8px; }
    ::-webkit-scrollbar-thumb { background: #1f1f30; border-radius: 4px; }
    ::-webkit-scrollbar-thumb:hover { background: #2f2f45; }

    /* Hamburger — hidden on desktop, shown on mobile */
    .hamburger { display: none; width: 38px; height: 38px; border: 1px solid #2a2a3a;
                 border-radius: 10px; background: #14141f; color: #c8c8d0; cursor: pointer;
                 align-items: center; justify-content: center; font-size: 18px; flex-shrink: 0;
                 font-family: inherit; }
    .hamburger:active { background: #7c6fe022; color: #7c6fe0; }

    /* Backdrop behind the mobile drawer */
    .backdrop { display: none; position: fixed; inset: 0; background: rgba(0,0,0,0.6);
                z-index: 99; backdrop-filter: blur(2px); }
    .backdrop.active { display: block; }

    /* ===== Tablet ===== */
    @media (max-width: 1024px) {
      .sidebar { width: 230px; min-width: 230px; }
      .memory { min-width: 150px; width: 150px; height: 210px; }
      .group-grid { grid-template-columns: repeat(auto-fill, minmax(140px, 1fr)); }
      .topbar, .memories, .groups { padding-left: 20px; padding-right: 20px; }
    }

    /* ===== Mobile ===== */
    @media (max-width: 768px) {
      body { overflow: auto; }
      .shell { display: block; height: auto; }

      /* Sidebar becomes a slide-out drawer */
      .sidebar { position: fixed; top: 0; left: 0; bottom: 0; width: 280px; min-width: 280px;
                 transform: translateX(-100%); transition: transform 0.22s ease;
                 z-index: 100; box-shadow: 2px 0 30px rgba(0,0,0,0.7); }
      .sidebar.open { transform: translateX(0); }

      .main { height: auto; min-height: 100vh; }

      .hamburger { display: inline-flex; }

      .topbar { padding: 10px 14px; gap: 10px; }
      .search { font-size: 14px; padding: 9px 14px; }
      .avatar { width: 32px; height: 32px; }
      .scope-tag { display: none; }  /* room-saver; still shown via drawer context */

      .memories { padding: 14px 14px 4px; }
      .memories-row { gap: 8px; -webkit-overflow-scrolling: touch; }
      .memory { min-width: 124px; width: 124px; height: 170px; border-radius: 12px; }
      .memory .m-label { font-size: 12px; bottom: 8px; left: 10px; right: 10px; }
      .memory .m-count { top: 8px; right: 8px; font-size: 10px; padding: 2px 6px; }

      .groups { padding: 6px 10px 40px; }
      .group { margin-bottom: 22px; }
      .group-head { flex-direction: column; gap: 2px; margin-bottom: 6px; align-items: flex-start; padding: 0 4px; }
      .group-date { font-size: 14px; }
      .group-meta { font-size: 11px; }
      .group-grid { grid-template-columns: repeat(auto-fill, minmax(100px, 1fr)); gap: 2px; }

      /* Touch-friendly tiles: remove hover scale (causes jitter on mobile) */
      .tile:hover { transform: none; box-shadow: none; }
      .tile:active { transform: scale(0.97); }

      .lb img, .lb video { max-width: 100vw; max-height: 100vh; border-radius: 0; }
      .lb-close { top: 10px; right: 14px; font-size: 36px;
                  width: 44px; height: 44px; display: flex; align-items: center; justify-content: center; }
      .lb-meta { bottom: 14px; font-size: 11px; padding: 0 14px; text-align: center; }
    }

    /* ===== Very small phones ===== */
    @media (max-width: 380px) {
      .memory { min-width: 108px; width: 108px; height: 150px; }
      .group-grid { grid-template-columns: repeat(3, 1fr); }
    }
  </style>
</head><body>

<div class="backdrop" id="backdrop" onclick="closeDrawer()"></div>

<div class="shell">

  <aside class="sidebar" id="sidebar">
    <div class="logo-wrap">
      <div class="logo">Photo<span class="dot">.</span></div>
      <div class="logo-sub">Home SOC Lab</div>
    </div>

    <div class="tree-section">
      <div class="tree-title">▸ Media</div>
      <div class="tree" id="tree"><div class="loading">loading…</div></div>
    </div>

    <div class="filters">
      <div class="filter-title">View</div>
      <button class="filter-btn active" data-kind="all">
        <span class="f-icon">🖼</span><span>All</span><span class="f-count" id="cnt-all">—</span>
      </button>
      <button class="filter-btn" data-kind="photos">
        <span class="f-icon">📷</span><span>Photos</span><span class="f-count" id="cnt-photos">—</span>
      </button>
      <button class="filter-btn" data-kind="videos">
        <span class="f-icon">🎬</span><span>Videos</span><span class="f-count" id="cnt-videos">—</span>
      </button>
      <a class="filter-btn" href="/nextcloud" style="text-decoration:none; margin-top:12px;">
        <span class="f-icon">☁</span><span>Nextcloud</span><span class="f-count">→</span>
      </a>
    </div>

    <div class="side-foot">
      <span>port 5001</span>
      <a href="/logout">logout</a>
    </div>
  </aside>

  <main class="main">
    <div class="topbar">
      <button class="hamburger" onclick="openDrawer()" aria-label="Menu">☰</button>
      <input class="search" id="search" placeholder="Search photos...">
      <span class="scope-tag" id="scope-tag" style="display:none"></span>
      <div class="avatar">R</div>
    </div>

    <section class="memories" id="memories-section" style="display:none">
      <div class="memories-row" id="memories-row"></div>
    </section>

    <section class="groups" id="groups">
      <div class="loading">loading photos…</div>
    </section>
  </main>
</div>

<div class="lb" id="lb" onclick="closeLB(event)">
  <span class="lb-close" onclick="closeLB(event)">×</span>
  <div id="lb-body"></div>
  <div class="lb-meta" id="lb-meta"></div>
</div>

<script>
const state = { scope: '', kind: 'all', search: '', feed: null };

// ------- Directory tree -------
async function loadTree() {
  const r = await fetch('/api/tree');
  const t = await r.json();
  document.getElementById('tree').innerHTML = '';
  const root = document.createElement('ul');
  root.appendChild(renderTreeNode(t, true));
  document.getElementById('tree').appendChild(root);
}

function renderTreeNode(node, isRoot) {
  const li = document.createElement('li');
  const hasKids = (node.children || []).length > 0;
  if (!hasKids) li.classList.add('leaf');
  if (isRoot) li.classList.add('expanded');

  const head = document.createElement('div');
  head.className = 'node' + (state.scope === node.path ? ' active' : '');
  head.innerHTML = `<span class="chev">▸</span><span class="icon">📁</span><span class="name">${escapeHtml(node.name)}</span><span class="count">${node.count}</span>`;
  head.addEventListener('click', (e) => {
    e.stopPropagation();
    if (hasKids) li.classList.toggle('expanded');
    setScope(node.path);
  });
  li.appendChild(head);

  if (hasKids) {
    const ul = document.createElement('ul');
    node.children.forEach(c => ul.appendChild(renderTreeNode(c, false)));
    li.appendChild(ul);
  }
  return li;
}

// ------- Feed -------
async function loadFeed() {
  document.getElementById('groups').innerHTML = '<div class="loading">loading photos…</div>';
  const qs = new URLSearchParams();
  if (state.scope) qs.set('path', state.scope);
  if (state.kind !== 'all') qs.set('type', state.kind);
  const r = await fetch('/api/feed?' + qs.toString());
  state.feed = await r.json();
  document.getElementById('cnt-all').textContent = state.feed.totals.total;
  document.getElementById('cnt-photos').textContent = state.feed.totals.photos;
  document.getElementById('cnt-videos').textContent = state.feed.totals.videos;
  renderFeed();
}

// Virtualized render: group headers + placeholder grids are cheap to create
// up front; tile DOM is only populated when the group scrolls near the viewport.
let _groupObserver = null;

function renderFeed() {
  const container = document.getElementById('groups');
  const q = state.search.trim().toLowerCase();
  const groups = state.feed.groups
    .map(g => ({ ...g, items: q ? g.items.filter(i =>
        i.name.toLowerCase().includes(q) || i.dir.toLowerCase().includes(q)) : g.items }))
    .filter(g => g.items.length);

  if (!groups.length) {
    container.innerHTML = '<div class="empty">No photos or videos here yet.<br>Drop files into the <code>media/</code> folder.</div>';
    return;
  }

  // Reset observer between renders
  if (_groupObserver) _groupObserver.disconnect();
  _groupObserver = new IntersectionObserver(onGroupIntersect, { rootMargin: '800px 0px' });

  // Render light shells only — tiles are hydrated lazily
  const TILE_H = 180; // approximate tile size used to reserve grid height
  const COLS = 5;     // approximate columns (just for height reservation — actual grid is responsive)
  const frag = document.createDocumentFragment();
  groups.forEach((g, idx) => {
    const rows = Math.ceil(g.items.length / COLS);
    const reserved = rows * TILE_H;
    const groupEl = document.createElement('div');
    groupEl.className = 'group';
    groupEl.dataset.idx = idx;
    groupEl.innerHTML = `
      <div class="group-head">
        <div class="group-date">${escapeHtml(g.label)}</div>
        <div class="group-meta">${metaLine(g)}</div>
      </div>
      <div class="group-grid" data-shell="1" style="min-height:${reserved}px"></div>
    `;
    groupEl._groupData = g;
    frag.appendChild(groupEl);
  });
  container.innerHTML = '';
  container.appendChild(frag);
  container.querySelectorAll('.group').forEach(el => _groupObserver.observe(el));
}

function onGroupIntersect(entries) {
  entries.forEach(entry => {
    if (!entry.isIntersecting) return;
    const el = entry.target;
    if (el.dataset.hydrated === '1') return;
    el.dataset.hydrated = '1';
    hydrateGroup(el);
    _groupObserver.unobserve(el);
  });
}

function hydrateGroup(el) {
  const g = el._groupData;
  if (!g) return;
  const grid = el.querySelector('.group-grid');
  grid.style.minHeight = '';
  grid.removeAttribute('data-shell');
  grid.innerHTML = g.items.map(it => tileHTML(it)).join('');
  grid.querySelectorAll('.tile').forEach(t => {
    t.addEventListener('click', () => openLB(t.dataset.path, t.dataset.kind, t.dataset.name));
  });
}

function metaLine(g) {
  const parts = [];
  if (g.photos) parts.push(g.photos + ' photo' + (g.photos > 1 ? 's' : ''));
  if (g.videos) parts.push(g.videos + ' video' + (g.videos > 1 ? 's' : ''));
  return parts.join(' · ');
}

function tileHTML(it) {
  if (it.is_image) {
    return `<div class="tile" data-path="${escapeAttr(it.path)}" data-kind="image" data-name="${escapeAttr(it.name)}">
              <img src="/thumb/${encodeURI(it.path)}" loading="lazy" decoding="async" alt="">
            </div>`;
  }
  // Video: server-side ffmpeg poster frame via /thumb/*, with a play overlay.
  // The onerror handler swaps to the gradient placeholder if ffmpeg is unavailable.
  return `<div class="tile" data-path="${escapeAttr(it.path)}" data-kind="video" data-name="${escapeAttr(it.name)}">
            <img src="/thumb/${encodeURI(it.path)}" loading="lazy" decoding="async" alt=""
                 onerror="this.onerror=null;this.replaceWith(Object.assign(document.createElement('div'),{className:'tile-video-ph',innerHTML:'<span class=\\'tile-play\\'>▶</span>'}));">
            <span class="vid-badge">▶</span>
            <span class="tile-play-overlay">▶</span>
          </div>`;
}

// ------- Memories -------
async function loadMemories() {
  const r = await fetch('/api/memories');
  const mem = await r.json();
  if (!mem.length) return;
  const row = document.getElementById('memories-row');
  row.innerHTML = mem.map(m => `
    <div class="memory" data-path="${escapeAttr(m.cover)}">
      <img src="/thumb/${encodeURI(m.cover)}" alt="">
      <span class="m-count">${m.count}</span>
      <div class="m-label">${escapeHtml(m.label)}</div>
    </div>
  `).join('');
  row.querySelectorAll('.memory').forEach(el => {
    el.addEventListener('click', () => openLB(el.dataset.path, 'image', ''));
  });
  document.getElementById('memories-section').style.display = 'block';
}

// ------- Scope / filter / search -------
function setScope(path) {
  state.scope = path || '';
  const tag = document.getElementById('scope-tag');
  if (state.scope) { tag.textContent = '📁 ' + state.scope; tag.style.display = 'inline-block'; }
  else tag.style.display = 'none';
  document.querySelectorAll('.tree .node').forEach(n => n.classList.remove('active'));
  loadFeed();
}

document.querySelectorAll('.filter-btn[data-kind]').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.filter-btn[data-kind]').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    state.kind = btn.dataset.kind;
    loadFeed();
  });
});

let _searchTimer = null;
document.getElementById('search').addEventListener('input', (e) => {
  const v = e.target.value;
  clearTimeout(_searchTimer);
  _searchTimer = setTimeout(() => {
    state.search = v;
    if (state.feed) renderFeed();
  }, 200);
});

// ------- Lightbox -------
function openLB(path, kind, name) {
  const body = document.getElementById('lb-body');
  if (kind === 'video') {
    body.innerHTML = `<video src="/media/${encodeURI(path)}" controls autoplay></video>`;
  } else {
    body.innerHTML = `<img src="/media/${encodeURI(path)}" alt="">`;
  }
  document.getElementById('lb-meta').textContent = name || path;
  document.getElementById('lb').classList.add('active');
}
function closeLB(e) {
  if (e && e.target.tagName === 'VIDEO') return;
  document.getElementById('lb').classList.remove('active');
  document.getElementById('lb-body').innerHTML = '';
}
document.addEventListener('keydown', e => { if (e.key === 'Escape') closeLB(); });

function escapeHtml(s) { return String(s).replace(/[&<>"']/g, c =>
  ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' }[c])); }
function escapeAttr(s) { return escapeHtml(s); }

// ------- Mobile drawer -------
function openDrawer() {
  document.getElementById('sidebar').classList.add('open');
  document.getElementById('backdrop').classList.add('active');
}
function closeDrawer() {
  document.getElementById('sidebar').classList.remove('open');
  document.getElementById('backdrop').classList.remove('active');
}
function autoCloseDrawerOnMobile() {
  if (window.matchMedia('(max-width: 768px)').matches) closeDrawer();
}
// Close drawer when user picks a folder or a filter on mobile
document.addEventListener('click', (e) => {
  if (e.target.closest('.tree .node') || e.target.closest('.filter-btn')) {
    autoCloseDrawerOnMobile();
  }
});
// Swipe-left to dismiss drawer on mobile
(function() {
  let startX = null;
  const side = document.getElementById('sidebar');
  side.addEventListener('touchstart', (e) => { startX = e.touches[0].clientX; });
  side.addEventListener('touchmove', (e) => {
    if (startX === null) return;
    const dx = e.touches[0].clientX - startX;
    if (dx < -60) { closeDrawer(); startX = null; }
  });
  side.addEventListener('touchend', () => { startX = null; });
})();

// ------- Boot -------
loadTree();
loadFeed();
loadMemories();
</script>
</body></html>
'''

NEXTCLOUD_HTML = r'''
<!DOCTYPE html>
<html><head>
  <title>Nextcloud Browser</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { background: #0f0e17; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
           color: #e0e0e0; min-height: 100vh; }
    .header { background: #0a0a14; border-bottom: 1px solid #1e1e2e;
              padding: 14px 24px; display: flex; align-items: center; gap: 16px; flex-wrap: wrap; }
    .logo { font-family: Georgia, serif; font-style: italic; color: #e0e0e0; font-weight: 700; font-size: 20px; }
    .logo .dot { color: #7c6fe0; }
    .nav-link { color: #aaa; font-size: 12px; text-decoration: none; padding: 6px 12px;
                border: 1px solid #2a2a3a; border-radius: 20px; }
    .nav-link:hover { border-color: #7c6fe0; color: #7c6fe0; }
    .search { background: #14141f; border: 1px solid #2a2a3a; border-radius: 20px;
              color: #e0e0e0; padding: 8px 14px; font-family: inherit; font-size: 12px; width: 240px; }
    .logout { margin-left: auto; color: #555; font-size: 12px; text-decoration: none; }
    .breadcrumb { padding: 10px 24px; font-size: 12px; color: #555; }
    .breadcrumb a { color: #7c6fe0; text-decoration: none; }
    .breadcrumb span { color: #444; margin: 0 6px; }
    .content { padding: 20px 24px; }
    .section-title { font-size: 10px; color: #7c6fe0; letter-spacing: 0.15em;
                     text-transform: uppercase; margin: 20px 0 12px; font-weight: 600; }
    .folders { display: flex; flex-wrap: wrap; gap: 10px; }
    .folder { background: #14141f; border: 1px solid #1f1f30; border-radius: 8px;
              padding: 10px 16px; text-decoration: none; color: #ccc; font-size: 13px; }
    .folder:hover { border-color: #7c6fe0; color: #7c6fe0; }
    .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(160px, 1fr)); gap: 10px; }
    .photo-card { background: #14141f; border: 1px solid #1f1f30; border-radius: 8px; overflow: hidden; }
    .photo-card img { width: 100%; height: 140px; object-fit: cover; display: block; }
    .photo-info { padding: 8px 10px; }
    .photo-name { font-size: 11px; color: #aaa; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .photo-size { font-size: 10px; color: #555; margin-top: 2px; }
    .photo-dl { display: block; text-align: center; background: #7c6fe022; color: #7c6fe0;
                text-decoration: none; font-size: 11px; padding: 5px; }
    .files-table { width: 100%; border-collapse: collapse; font-size: 12px; }
    .files-table th { text-align: left; color: #555; padding: 8px 12px; border-bottom: 1px solid #222; }
    .files-table td { padding: 8px 12px; border-bottom: 1px solid #14141f; }
    .dl-btn { color: #7c6fe0; text-decoration: none; font-size: 11px; }
    .empty { color: #444; font-size: 13px; padding: 40px 0; text-align: center; }
    @media (max-width: 768px) {
      .header { padding: 12px 14px; gap: 10px; }
      .search { width: 100%; min-width: 0; order: 3; }
      .logo { font-size: 17px; }
      .nav-link { font-size: 11px; padding: 5px 10px; }
      .content { padding: 14px; }
      .grid { grid-template-columns: repeat(auto-fill, minmax(110px, 1fr)); gap: 6px; }
      .photo-card img { height: 110px; }
      .files-table th:nth-child(3), .files-table td:nth-child(3) { display: none; }
      .breadcrumb { padding: 8px 14px; }
    }
  </style>
</head><body>
<div class="header">
  <span class="logo">Photo<span class="dot">.</span></span>
  <a class="nav-link" href="/">← Library</a>
  <form method="GET" action="/nextcloud" style="display:inline">
    <input type="hidden" name="path" value="{{ path }}">
    <input class="search" type="text" name="search" placeholder="Search Nextcloud..." value="{{ search }}">
  </form>
  <a class="logout" href="/logout">logout</a>
</div>
<div class="breadcrumb">
  {% for name, bpath in breadcrumbs %}
    {% if not loop.last %}<a href="/nextcloud?path={{ bpath }}">{{ name }}</a><span>/</span>
    {% else %}{{ name }}{% endif %}
  {% endfor %}
</div>
<div class="content">
  {% if folders %}
    <div class="section-title">Folders ({{ folders|length }})</div>
    <div class="folders">
      {% for f in folders %}<a class="folder" href="/nextcloud?path={{ f.path }}">📁 {{ f.name }}</a>{% endfor %}
    </div>
  {% endif %}
  {% if photos %}
    <div class="section-title">Photos ({{ photos|length }})</div>
    <div class="grid">
      {% for p in photos %}
      <div class="photo-card">
        <img src="/nc-thumb?path={{ p.path }}" loading="lazy">
        <div class="photo-info">
          <div class="photo-name">{{ p.name }}</div>
          <div class="photo-size">{{ human_size(p.size) }}</div>
        </div>
        <a class="photo-dl" href="/download?source=nextcloud&path={{ p.path }}">⬇ Download</a>
      </div>
      {% endfor %}
    </div>
  {% endif %}
  {% if files %}
    <div class="section-title">Files ({{ files|length }})</div>
    <table class="files-table">
      <thead><tr><th>Name</th><th>Size</th><th>Modified</th><th></th></tr></thead>
      <tbody>
      {% for f in files %}
        <tr><td>{{ f.name }}</td><td>{{ human_size(f.size) }}</td><td>{{ f.modified }}</td>
            <td><a class="dl-btn" href="/download?source=nextcloud&path={{ f.path }}">⬇</a></td></tr>
      {% endfor %}
      </tbody>
    </table>
  {% endif %}
  {% if not folders and not photos and not files %}
    <div class="empty">This folder is empty.</div>
  {% endif %}
</div>
</body></html>
'''


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=False)
