import json, os, uuid
from datetime import datetime, timezone
from django.conf import settings
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def record(action, obj, **details):
    event = {'id': uuid.uuid4().hex, 'time': datetime.now(timezone.utc).isoformat(), 'action': action, 'object': str(obj), 'details': details}
    nonce = os.urandom(12)
    payload = nonce + AESGCM(settings.LOG_KEY_FILE.read_bytes()).encrypt(nonce, json.dumps(event, sort_keys=True).encode(), b'journal')
    folder = settings.RUNTIME / 'journal' / 'pending'
    staging = folder / (event['id'] + '.tmp')
    staging.write_bytes(payload)
    staging.rename(folder / (event['id'] + '.evt'))
    return event

def mutation(sender, instance, created=False, **kwargs):
    record('create' if created else 'update', f'{sender._meta.label}:{instance.pk}')

def deletion(sender, instance, **kwargs):
    record('delete', f'{sender._meta.label}:{instance.pk}')

def relations(sender, instance, action, pk_set=None, **kwargs):
    record('permissions', f'{instance._meta.label}:{instance.pk}', operation=action)

def db_connected(sender, connection, **kwargs):
    record('db_connect', connection.alias)

def signed_in(sender, request, user, **kwargs):
    record('login', f'user:{user.pk}')

def signed_out(sender, request, user, **kwargs):
    record('logout', f'user:{user.pk if user else 0}')

def login_failed(sender, credentials, request, **kwargs):
    record('login_refused', 'authentication')
