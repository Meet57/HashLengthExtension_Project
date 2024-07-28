from urllib.parse import urlparse, parse_qs
from django.http import HttpResponseForbidden
from django.shortcuts import get_object_or_404, render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from .models import Image
from .forms import ImageForm, RegistrationForm
import hashlib
import hmac as hmac_lib
import HashTools

secret_key = b"ABC"
use_hmac = False
hash_function = "md5"

def create_signature(secret, data, hash_function="md5", use_hmac=False):
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
        signature = hmac_lib.new(secret, data, hash_obj).hexdigest()
    else:
        signature = hash_obj(secret + data).hexdigest()

    return signature

def verify_signature(secret, data, signature, hash_function="md5", use_hmac=False):
    computed_sig = create_signature(secret, data, hash_function, use_hmac)
    print(computed_sig, signature)
    return computed_sig == signature

def perform_extension_attack(secret_length, original_data, append_data, original_signature, hash_function="md5"):
    magic = HashTools.new(hash_function)
    new_data, new_sig = magic.extension(
        secret_length=secret_length,
        original_data=original_data,
        append_data=append_data,
        signature=original_signature
    )
    return new_data, new_sig

def safe_decode(byte_data):
    try:
        return byte_data.decode('utf-8')
    except UnicodeDecodeError:
        return byte_data.decode('latin1')

def is_valid_md5_signature(signature):
    return len(signature) == 32 and all(c in '0123456789abcdef' for c in signature.lower())


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

        if request.user.username == image.owner.username:
            data = f"id={image.id}&owner={image.owner.username}&download=true"
        else:
            data = f"id={image.id}&owner={image.owner.username}"

        mac = create_signature(secret_key, data.encode(), hash_function, use_hmac)
        images_data.append({
            'id': image.id,
            'user': image.owner.username,
            'image': image.image,
            'download': request.user.username == image.owner.username,
            'mac': mac
        })

    return render(request, 'hash_extension/home.html', {'images': images_data})


@login_required
def view_image(request):
    image_id = request.GET.get('id')
    owner = request.GET.get('owner')
    mac = request.GET.get('mac')
    download = request.GET.get('download')

    if not image_id or not owner or not mac:
        return HttpResponseForbidden("Missing required parameters")

    image = get_object_or_404(Image, id=image_id)

    if download == "true":
        data = f"id={image.id}&owner={owner}&download=true".encode()
    else:
        data = f"id={image.id}&owner={owner}".encode()

    # Verify the signature
    if verify_signature(secret_key, data, mac, hash_function, use_hmac):
        return render(request, 'hash_extension/view_image.html', {'image': image, 'is_owner': (download == "true")})
    else:
        return render(request, 'hash_extension/view_image.html', {'image': image, 'is_owner': (download == "true")})


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

        # Parse the URL
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        image_id = query_params.get('id', [None])[0]
        original_owner = query_params.get('owner', [None])[0]
        original_signature = query_params.get('mac', [None])[0]

        if not image_id or not original_owner or not original_signature:
            return render(request, 'hash_extension/perform_attack.html', {'error': 'Invalid URL format'})

        # Verify the original signature
        original_data = f"id={image_id}&owner={original_owner}".encode()
        if not verify_signature(secret_key, original_data, original_signature, "md5", use_hmac):
            return render(request, 'hash_extension/perform_attack.html', {'error': 'Invalid signature'})

        # Generate new data and signature if not using HMAC
        if not use_hmac:
            append_data = b"&download=true"
            try:
                new_data, new_sig = perform_extension_attack(len(secret_key), original_data, append_data, original_signature, hash_function)
                new_valid = verify_signature(secret_key, new_data, new_sig, hash_function, use_hmac)
                if new_valid:
                    new_url = parsed_url.scheme + "://" + parsed_url.netloc + "/view_image/?" + str(new_data).replace("b'","").replace("'", "") + "&mac=" + new_sig

                    return render(request, 'hash_extension/attack_result.html', {'new_url': new_url, 'new_sig': new_sig})
                else:
                    return render(request, 'hash_extension/perform_attack.html', {'error': 'New signature verification failed'})
            except Exception as e:
                return render(request, 'hash_extension/perform_attack.html', {'error': f'Extension attack failed: {e}'})
        else:
            return render(request, 'hash_extension/perform_attack.html', {'error': 'Extension attack not applicable with HMAC'})

    return render(request, 'hash_extension/perform_attack.html')

def project_brief(request):
    return render(request, 'hash_extension/project_brief.html')

def logout_view(request):
    logout(request)
    return redirect('login')
