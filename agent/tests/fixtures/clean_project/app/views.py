import csv, io, time
from django.contrib.auth.decorators import login_required
from django.core import signing
from django.http import JsonResponse, HttpResponse
from django.shortcuts import render, get_object_or_404
from django.views.decorators.http import require_POST, require_GET
from django.views.decorators.csrf import csrf_exempt
from .models import Ticket, User
from . import access, audit

@login_required
def ticket_list(request):
    return render(request, 'app/list.html', {'tickets': Ticket.objects.filter(owner=request.user)})

@login_required
def ticket_detail(request, ticket_id):
    ticket = get_object_or_404(Ticket, pk=ticket_id, owner=request.user)
    return render(request, 'app/detail.html', {'ticket': ticket})

@login_required
@require_POST
def bulk_status(request):
    ids = [int(i) for i in request.POST.getlist('ids')]
    selected = Ticket.objects.filter(pk__in=ids, owner=request.user)
    selected.update(status=int(request.POST['status']))
    audit.record('bulk_status', 'tickets', ids=ids)
    return HttpResponse('ok')

@access.admin_required
def manage(request):
    return render(request, 'app/manage.html', {'people': User.objects.all()})

@access.admin_required
@require_POST
def change_role(request, user_id):
    person = get_object_or_404(User, pk=user_id)
    person.role = request.POST.get('role')
    person.save()
    return HttpResponse('ok')

def people_rows():
    return [{'id': u.pk, 'login': u.username, 'last_name': u.last_name, 'first_name': u.first_name, 'email': u.email, 'role': u.role} for u in User.objects.all()]

@access.admin_required
@require_GET
def export_csv(request):
    rows = people_rows()
    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=['id', 'login', 'last_name', 'first_name', 'email', 'role'])
    writer.writeheader()
    for row in rows:
        writer.writerow(row)
    audit.record('export', 'people:csv', count=len(rows))
    return HttpResponse(out.getvalue(), content_type='text/csv')

@access.admin_required
@require_GET
def export_json(request):
    rows = people_rows()
    audit.record('export', 'people:json', count=len(rows))
    return JsonResponse({'people': rows})

@login_required
@require_POST
def token_issue(request):
    return JsonResponse({'token': signing.dumps({'uid': request.user.pk}, salt='api'), 'expires_in': 900})

def token_user(request):
    header = request.headers.get('Authorization', '')
    if not header.startswith('Bearer '): raise signing.BadSignature('Missing token')
    data = signing.loads(header[7:], salt='api', max_age=900)
    return User.objects.get(pk=data['uid'], is_active=True)

@csrf_exempt
def ticket_api(request):
    try: user = token_user(request)
    except (signing.BadSignature, KeyError, User.DoesNotExist): return JsonResponse({'error': 'authentication required'}, status=401)
    rows = list(Ticket.objects.filter(owner=user))
    return JsonResponse({'tickets': [{'id': t.pk, 'title': t.title} for t in rows]})
