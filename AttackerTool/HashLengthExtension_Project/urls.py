# HashLengthExtension_Project/urls.py
from django.contrib import admin
from django.urls import path
from hash_extension import views

urlpatterns = [
    path('', views.perform_attack, name='perform_attack'),
]

# Serving media files during development
from django.conf import settings
from django.conf.urls.static import static

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)