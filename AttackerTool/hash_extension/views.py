from urllib.parse import urlparse, parse_qs
from django.shortcuts import render
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