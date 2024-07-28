from django.contrib import admin
from .models import Image

@admin.register(Image)
class ImageAdmin(admin.ModelAdmin):
    list_display = ('title', 'owner', 'image')
    search_fields = ('title', 'owner__username')