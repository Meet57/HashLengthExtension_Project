# hash_extension/forms.py
from django import forms
from .models import Image
from django.contrib.auth.models import User
from django.contrib.auth.forms import UserCreationForm

class ImageForm(forms.ModelForm):
    class Meta:
        model = Image
        fields = ['title', 'image']
        widgets = {
            'title': forms.TextInput(attrs={
                'class': 'w-full p-3 border border-gray-300 rounded-lg focus:outline-none focus:border-green-500'
            }),
            'image': forms.ClearableFileInput(attrs={
                'class': 'w-full p-3 border border-gray-300 rounded-lg focus:outline-none focus:border-green-500'
            })
        }

class RegistrationForm(UserCreationForm):
   

    class Meta:
        model = User
        fields = ['username', 'password1', 'password2']
        widgets = {
            'username': forms.TextInput(attrs={
                'class': 'w-full p-3 border border-gray-300 rounded-lg focus:outline-none focus:border-green-500'
            }),
            'password1': forms.PasswordInput(attrs={
                'class': 'w-full p-3 border border-gray-300 rounded-lg focus:outline-none focus:border-green-500'
            }),
            'password2': forms.PasswordInput(attrs={
                'class': 'w-full p-3 border border-gray-300 rounded-lg focus:outline-none focus:border-green-500'
            }),
        }
