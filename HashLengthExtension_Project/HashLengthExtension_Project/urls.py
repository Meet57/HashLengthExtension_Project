# HashLengthExtension_Project/urls.py
from django.contrib import admin
from django.urls import path
from hash_extension import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('login/', views.login_view, name='login'),
    path('register/', views.register_view, name='register'),
    path('logout/', views.logout_view, name='logout'),
    path('', views.home, name='home'),
    path('upload_image/', views.upload_image, name='upload_image'),
    path('view_image/', views.view_image, name='view_image'),
    path('perform_attack/', views.perform_attack, name='perform_attack'),
]

# Serving media files during development
from django.conf import settings
from django.conf.urls.static import static

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)