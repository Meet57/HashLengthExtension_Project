import hashlib
import hmac as hmac_lib
from urllib.parse import urlparse

from django.http import HttpResponseForbidden
from django.shortcuts import get_object_or_404
import HashTools
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from .models import Image
from .forms import ImageForm, RegistrationForm

secret_key = b"ABC"

def login_view(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('home')
    return render(request, 'hash_extension/login.html')

def register_view(request):
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            form.save()
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password1')
            user = authenticate(username=username, password=password)
            login(request, user)
            return redirect('home')
    else:
        form = RegistrationForm()
    return render(request, 'hash_extension/register.html', {'form': form})

@login_required
def home(request):
    images = Image.objects.all()
    images_data = []

    for image in images:
        data = f"{image.id}/{request.user.username}"
        mac = create_signature(secret_key, data)
        images_data.append({
            'id': image.id,
            'user': request.user.username,
            'image': image.image,
            'mac': mac
        })

        print(images_data)

    return render(request, 'hash_extension/home.html', {'images': images_data})

@login_required
def view_image(request, image_id, owner, mac):
    image = get_object_or_404(Image, id=image_id)
    data = f"{image.id}/{image.owner.username}"
    expected_mac = create_signature(secret_key, data)

    if expected_mac == mac:
        is_owner = (image.owner.username == owner)
        return render(request, 'hash_extension/view_image.html', {'image': image, 'is_owner': is_owner})
    else:
        return render(request, 'hash_extension/view_image.html', {'image': image, 'is_owner': False})

@login_required
def upload_image(request):
    if request.method == 'POST':
        form = ImageForm(request.POST, request.FILES)
        if form.is_valid():
            image = form.save(commit=False)
            image.owner = request.user
            image.save()
            return redirect('home')
    else:
        form = ImageForm()
    return render(request, 'hash_extension/upload_image.html', {'form': form})


@login_required
def perform_attack(request):
    if request.method == 'POST':
        url = request.POST['url']
        new_owner = request.POST['new_owner']

        # Parse the URL
        parsed_url = urlparse(url)
        path_parts = parsed_url.path.split('/')
        if len(path_parts) < 5:
            return render(request, 'hash_extension/perform_attack.html', {'error': 'Invalid URL format'})

        image_id = path_parts[2]
        original_owner = path_parts[3]
        original_signature = path_parts[4]

        # Generate new data and signature
        # original_data = f"{image_id}".encode()
        # append_data = f"/{new_owner}".encode()
        # new_data, new_sig = perform_extension_attack(len(secret_key), original_data, append_data, original_signature.encode(), "sha256")

        data = f"{image_id}/{new_owner}"

        new_sig = create_signature(secret_key, data)

        # Construct new URL
        new_url = f"{parsed_url.scheme}://{parsed_url.netloc}/view_image/{image_id}/{new_owner}/{new_sig}/"

        return render(request, 'hash_extension/attack_result.html', {'new_url': new_url, 'new_sig': new_sig})

    return render(request, 'hash_extension/perform_attack.html')

def logout_view(request):
    logout(request)
    return redirect('login')


def create_signature(secret, data, hash_function="sha256", use_hmac=False):
    if hash_function == "sha1":
        hash_obj = hashlib.sha1
    elif hash_function == "md5":
        hash_obj = hashlib.md5
    elif hash_function == "sha256":
        hash_obj = hashlib.sha256
    elif hash_function == "sha512":
        hash_obj = hashlib.sha512
    else:
        raise ValueError("Invalid hash function")

    if use_hmac:
        signature = hmac_lib.new(secret, data.encode(), hash_obj).hexdigest()
    else:
        signature = hash_obj(secret + data.encode()).hexdigest()

    return signature


def verify_signature(secret, data, signature, hash_function="sha256", use_hmac=False):
    computed_sig = create_signature(secret, data, hash_function, use_hmac)
    return computed_sig == signature


def perform_extension_attack(secret_length, original_data, append_data, original_signature, hash_function="sha256"):
    magic = HashTools.new(hash_function)
    new_data, new_sig = magic.extension(
        secret_length=secret_length,
        original_data=original_data,
        append_data=append_data,
        signature=original_signature
    )
    return new_data, new_sig
