from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.hashers import make_password, check_password
from rest_framework_simplejwt.tokens import RefreshToken
from .models import User, RegistryUser, ProductOffer, Limits
from django.urls import reverse
from datetime import datetime, timedelta
import jwt
from django.conf import settings
import re
import uuid
from django.utils import timezone
from django.db import transaction
from django.contrib.auth import user_logged_in

def home(request):
    return render(request, 'dashboard/home.html')

def login_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard:profile')
    
    if request.method == 'POST':
        email_or_device_id = request.POST.get('email_or_device_id')
        password = request.POST.get('password')
        print(f"Login attempt with email_or_device_id: {email_or_device_id}, password provided: {bool(password)}")
        
        user = authenticate(request=request, email_or_device_id=email_or_device_id, password=password)
        if user:
            print(f"Attempting login for user: {user.user_registry_id}, user_logged_in receivers: {len(user_logged_in.receivers)}")
            login(request, user, backend='dashboard.auth.UserRegistryBackend')
            registry_user = RegistryUser.objects.using('user_registry').get(id=user.user_registry_id)
            refresh = RefreshToken.for_user(user)
            user.access_token = str(refresh.access_token)
            user.refresh_token = str(refresh)
            registry_user.access_token = user.access_token
            registry_user.refresh_token = user.refresh_token
            user.save()
            registry_user.save(using='user_registry')
            
            response = redirect('dashboard:profile')
            response.set_cookie(
                'access_token_cookie',
                user.access_token,
                secure=False,
                httponly=True,
                samesite='Lax'
            )
            response.set_cookie(
                'refresh_token_cookie',
                user.refresh_token,
                secure=False,
                httponly=True,
                samesite='Lax'
            )
            messages.success(request, 'Logged in successfully!')
            print(f"Login successful for user: {email_or_device_id}")
            return response
        else:
            messages.error(request, 'Invalid credentials or device ID.')
            print(f"Login failed for email_or_device_id: {email_or_device_id}")
    
    return render(request, 'dashboard/login.html')

def signup_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard:profile')
    
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')
        phone_number = request.POST.get('phone_number')
        print(f"Signup attempt for email: {email}")
        
        if not email or not password or not confirm_password:
            messages.error(request, 'Email and password are required.')
            print("Signup failed: Missing email or password")
            return render(request, 'dashboard/signup.html')
        
        if password != confirm_password:
            messages.error(request, 'Passwords do not match.')
            print("Signup failed: Passwords do not match")
            return render(request, 'dashboard/signup.html')
        
        if not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email):
            messages.error(request, 'Invalid email.')
            print("Signup failed: Invalid email")
            return render(request, 'dashboard/signup.html')
        
        if RegistryUser.objects.using('user_registry').filter(email=email).exists():
            messages.error(request, 'Email already registered.')
            print(f"Signup failed: Email already registered: {email}")
            return render(request, 'dashboard/signup.html')
        
        user_id = str(uuid.uuid4())
        device_id = f"device-{user_id[:8]}"
        now = timezone.now()
        hashed_password = make_password(password)
        print(f"Hashed password for signup: {hashed_password}")
        
        try:
            with transaction.atomic(using='user_registry'):
                registry_user = RegistryUser.objects.using('user_registry').create(
                    id=user_id,
                    email=email,
                    password=hashed_password,
                    phone_num=phone_number,
                    device_id=device_id,
                    created_at=now,
                    updated_at=now,
                    activated=False
                )
                print(f"Created RegistryUser with id: {user_id}")
                
                basic_offer = ProductOffer.objects.filter(name='Basic').first()
                basic_offer_id = basic_offer.id if basic_offer else None
                print(f"Using product_offer_id: {basic_offer_id}")
                user = User.objects.create(
                    user_registry_id=user_id,
                    email=email,
                    phone_num=phone_number,
                    product_offer_id=basic_offer_id,
                    is_admin=False,
                    created_at=now
                )
                print(f"Created terrapipe user with user_registry_id: {user_id}")
                
                print(f"Before login, user_logged_in receivers: {len(user_logged_in.receivers)}")
                login(request, user, backend='dashboard.auth.UserRegistryBackend')
                refresh = RefreshToken.for_user(user)
                user.access_token = str(refresh.access_token)
                user.refresh_token = str(refresh)
                registry_user.access_token = user.access_token
                registry_user.refresh_token = user.refresh_token
                user.save()
                registry_user.save(using='user_registry')
                
                response = redirect('dashboard:profile')
                response.set_cookie(
                    'access_token_cookie',
                    user.access_token,
                    secure=False,
                    httponly=True,
                    samesite='Lax'
                )
                response.set_cookie(
                    'refresh_token_cookie',
                    user.refresh_token,
                    secure=False,
                    httponly=True,
                    samesite='Lax'
                )
                messages.success(request, 'Account created successfully!')
                print(f"Signup successful for user: {email}")
                return response
        except Exception as e:
            print(f"Signup failed with error: {str(e)}")
            RegistryUser.objects.using('user_registry').filter(id=user_id).delete()
            print(f"Cleaned up RegistryUser with id: {user_id}")
            messages.error(request, 'Signup failed. Please try again.')
            return render(request, 'dashboard/signup.html')
    
    return render(request, 'dashboard/signup.html')

def profile_view(request):
    if not request.user.is_authenticated:
        messages.error(request, 'Please log in to view your profile.')
        return redirect('dashboard:login')
    return render(request, 'dashboard/profile.html')

def logout_view(request):
    if request.user.is_authenticated:
        user = User.objects.get(user_registry_id=request.user.user_registry_id)
        registry_user = RegistryUser.objects.using('user_registry').get(id=user.user_registry_id)
        user.access_token = None
        user.refresh_token = None
        registry_user.access_token = None
        registry_user.refresh_token = None
        user.save()
        registry_user.save(using='user_registry')
        logout(request)
    response = redirect('dashboard:login')
    response.delete_cookie('access_token_cookie')
    response.delete_cookie('refresh_token_cookie')
    messages.success(request, 'Logged out successfully!')
    print("User logged out")
    return response

def forgot_password_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard:profile')
    
    if request.method == 'POST':
        email = request.POST.get('email')
        print(f"Forgot password request for email: {email}")
        if not email:
            messages.error(request, 'Email is required.')
            print("Forgot password failed: Email required")
            return render(request, 'dashboard/forgot_password.html')
        
        if not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email):
            messages.error(request, 'Invalid email.')
            print("Forgot password failed: Invalid email")
            return render(request, 'dashboard/forgot_password.html')
        
        user = RegistryUser.objects.using('user_registry').filter(email=email).first()
        if not user:
            messages.error(request, 'Email not found.')
            print(f"Forgot password failed: Email not found: {email}")
            return render(request, 'dashboard/forgot_password.html')
        
        token = jwt.encode(
            {'email': email, 'exp': datetime.utcnow() + timedelta(hours=1)},
            settings.SIMPLE_JWT['SIGNING_KEY'],
            algorithm=settings.SIMPLE_JWT['ALGORITHM']
        )
        
        confirm_url = request.build_absolute_uri(reverse('dashboard:reset_password', args=[token]))
        html = f"""
        <p>Click the link below to reset your password:</p>
        <p><a href="{confirm_url}">{confirm_url}</a></p>
        """
        send_email(email, 'Password Reset', html)
        
        messages.success(request, 'Password reset email sent.')
        print(f"Password reset email sent to: {email}")
        return redirect('dashboard:login')
    
    return render(request, 'dashboard/forgot_password.html')

def reset_password_view(request, token):
    if request.user.is_authenticated:
        return redirect('dashboard:profile')
    
    try:
        payload = jwt.decode(token, settings.SIMPLE_JWT['SIGNING_KEY'], algorithms=[settings.SIMPLE_JWT['ALGORITHM']])
        email = payload['email']
        user = RegistryUser.objects.using('user_registry').filter(email=email).first()
        print(f"Reset password attempt for email: {email}")
        if not user:
            messages.error(request, 'Invalid or expired reset link.')
            print("Reset password failed: User not found")
            return render(request, 'dashboard/reset_password.html')
        
        if request.method == 'POST':
            password = request.POST.get('password')
            confirm_password = request.POST.get('confirm_password')
            
            if not password or not confirm_password:
                messages.error(request, 'Password is required.')
                print("Reset password failed: Password required")
                return render(request, 'dashboard/reset_password.html')
            
            if password != confirm_password:
                messages.error(request, 'Passwords do not match.')
                print("Reset password failed: Passwords do not match")
                return render(request, 'dashboard/reset_password.html')
            
            if check_password(password, user.password):
                messages.error(request, 'New password cannot be the same as the old password.')
                print("Reset password failed: New password same as old")
                return render(request, 'dashboard/reset_password.html')
            
            hashed_password = make_password(password)
            print(f"New hashed password for reset: {hashed_password}")
            user.password = hashed_password
            user.updated_at = timezone.now()
            user.save(using='user_registry')
            local_user = User.objects.filter(user_registry_id=user.id).first()
            if local_user:
                local_user.updated_at = timezone.now()
                local_user.save()
            
            messages.success(request, 'Password updated successfully! Please log in.')
            print(f"Password reset successful for user: {email}")
            return redirect('dashboard:login')
        
        return render(request, 'dashboard/reset_password.html')
    
    except jwt.ExpiredSignatureError:
        messages.error(request, 'Reset link has expired.')
        print("Reset password failed: Expired token")
        return render(request, 'dashboard/reset_password.html')
    except jwt.InvalidTokenError:
        messages.error(request, 'Invalid reset link.')
        print("Reset password failed: Invalid token")
        return render(request, 'dashboard/reset_password.html')

def update_view(request):
    if not request.user.is_authenticated:
        messages.error(request, 'Please log in to update your profile.')
        return redirect('dashboard:login')
    
    if request.method == 'POST':
        phone_number = request.POST.get('phone_number')
        coordinates = request.POST.get('coordinates')
        password = request.POST.get('password')
        print(f"Profile update attempt for user: {request.user.user_registry_id}")
        
        user = User.objects.get(user_registry_id=request.user.user_registry_id)
        registry_user = RegistryUser.objects.using('user_registry').get(id=user.user_registry_id)
        
        updated = False
        if phone_number and phone_number != user.phone_num:
            user.phone_num = phone_number
            registry_user.phone_num = phone_number
            updated = True
            messages.success(request, 'Phone number updated.')
            print("Phone number updated")
        
        if coordinates:
            try:
                coordinates_json = json.loads(coordinates)
                if isinstance(coordinates_json, dict) and 'lat' in coordinates_json and 'lng' in coordinates_json:
                    if coordinates_json != user.coordinates:
                        user.coordinates = coordinates_json
                        registry_user.lat_lng = coordinates_json
                        updated = True
                        messages.success(request, 'Coordinates updated.')
                        print("Coordinates updated")
                else:
                    messages.error(request, 'Invalid coordinates format. Use {"lat": number, "lng": number}.')
                    print("Update failed: Invalid coordinates format")
            except json.JSONDecodeError:
                messages.error(request, 'Invalid JSON format for coordinates.')
                print("Update failed: Invalid JSON coordinates")
        
        if password and not check_password(password, registry_user.password):
            hashed_password = make_password(password)
            print(f"New hashed password for update: {hashed_password}")
            registry_user.password = hashed_password
            updated = True
            messages.success(request, 'Password updated.')
            print("Password updated")
        
        if updated:
            user.updated_at = timezone.now()
            registry_user.updated_at = timezone.now()
            user.save()
            registry_user.save(using='user_registry')
            print("Profile updated successfully")
        else:
            messages.info(request, 'Nothing to update.')
            print("No updates made")
        
        return redirect('dashboard:profile')
    
    return render(request, 'dashboard/update.html')

def send_email(to_email, subject, html_content):
    from django.core.mail import send_mail
    send_mail(
        subject=subject,
        message='',
        html_message=html_content,
        from_email='no-reply@terrapipe.com',
        recipient_list=[to_email],
        fail_silently=True,
    )
    print(f"Email sent to: {to_email}")