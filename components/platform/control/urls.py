from django.urls import path
from . import views, console, workspace, datacenter

urlpatterns = [path('core/api/datacenter', datacenter.endpoint),
               path('core/api/datacenter/floors/<str:floor>', datacenter.endpoint),
               path('core/api/registry', workspace.inventory),
               path('core/api/noc', workspace.inventory, {'screen':'noc'}),
               path('core/api/library', workspace.library), path('core/api/library/<slug:article>', workspace.library),
               path('core/api/console/<str:device>', console.endpoint),
               path('core/api/console/<str:device>/<str:action>', console.endpoint), path('core/', views.page), path('core/assets/<str:name>', views.asset),
               path('core/api/session', views.session), path('core/api/login', views.sign_in),
               path('core/api/logout', views.sign_out), path('core/api/password', views.change_password),
               path('core/api/users', views.users), path('core/api/audit', views.audits),
               path('core/api/devices', views.devices), path('core/api/devices/<str:device>', views.devices)]
