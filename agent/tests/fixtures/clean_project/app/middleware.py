from django.core.exceptions import PermissionDenied
from . import audit
class AuditMiddleware:
    def __init__(self, get_response): self.get_response = get_response
    def __call__(self, request):
        response = self.get_response(request)
        if request.user.is_authenticated:
            audit.record('request', request.path, method=request.method, status=response.status_code)
        return response
    def process_exception(self, request, exception):
        if isinstance(exception, PermissionDenied):
            audit.record('access_denied', request.path)
        return None
