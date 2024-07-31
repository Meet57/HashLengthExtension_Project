# project/urls.py
from django import views
from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('hash_extension.urls')),  # Include the app's URLs
    path('toggle/', views.toggle_security, name='toggle_hmac'),
]
