from django.urls import path, include
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('hooks/', views.hooks, name='hooks'),
    path('hook/<slug:slug>', views.hook, name='hook'),
    path('restart/', views.restart, name='restart'),
    path('faq/', views.faq, name='faq'),
    path('uploads/', views.uploads, name='uploads'),
    path('account/', views.account, name='account'),
    path('command/create/', views.create_command, name='create-command'),
    path('command/<int:pk>/', views.command_response, name='response-command'),
    path('delete_file/<int:file_id>/', views.delete_file, name='delete_file'),
]