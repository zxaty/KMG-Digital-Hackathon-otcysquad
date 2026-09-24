from django.urls import path
from django.contrib.auth import views as auth
from django.contrib.auth.decorators import login_required
from app import views as v
patterns = [
    path('login/', auth.LoginView.as_view(template_name='app/login.html'), name='login'),
    path('logout/', login_required(auth.LogoutView.as_view()), name='logout'),
    path('tickets/', login_required(v.ticket_list), name='list'),
    path('tickets/<int:ticket_id>/', login_required(v.ticket_detail), name='view'),
    path('tickets/bulk/', login_required(v.bulk_status), name='bulk'),
    path('manage/', v.manage, name='manage'),
    path('manage/users/<int:user_id>/role/', v.change_role, name='role'),
    path('exports/people.csv', v.export_csv, name='csv'),
    path('exports/people.json', v.export_json, name='json'),
    path('api/token/', v.token_issue, name='token'),
    path('api/v1/tickets/', v.ticket_api, name='api_tickets'),
]
urlpatterns = [path('', __import__('django.urls').urls.include((patterns, 'app'), namespace='app'))]
