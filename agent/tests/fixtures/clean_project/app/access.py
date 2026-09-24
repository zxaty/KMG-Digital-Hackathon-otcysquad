from functools import wraps
from django.core.exceptions import PermissionDenied
from django.contrib.auth.decorators import login_required
def administrator(user):
    return user.is_authenticated and user.is_active and user.role == 'administrator'
def admin_required(view):
    @login_required
    @wraps(view)
    def wrapped(request, *args, **kwargs):
        if not administrator(request.user): raise PermissionDenied
        return view(request, *args, **kwargs)
    return wrapped
