from django.urls import path
from . import views

urlpatterns = [path('core/', views.page), path('core/assets/<str:name>', views.asset),
               path('core/api/session', views.session), path('core/api/login', views.sign_in),
               path('core/api/logout', views.sign_out), path('core/api/password', views.change_password),
               path('core/api/users', views.users), path('core/api/audit', views.audits),
               path('core/api/devices', views.devices), path('core/api/devices/<str:device>', views.devices)]
