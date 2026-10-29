"""
CaseVault Authentication Views
Organization: Northbridge Cyber Response
Module: CYS22301 Software and Platform Security (Level 6)

Handles login, session elevation with RFC 6238 TOTP MFA via django-otp,
TOTP onboarding, and audit logging for identity events (ADR-0001, ADR-0006).
"""

import io

import qrcode
import qrcode.image.svg
from django.contrib import messages
from django.contrib.auth import login as auth_login
from django.contrib.auth import logout as auth_logout
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect, render
from django.views.decorators.http import require_http_methods
from django_otp import login as otp_login
from django_otp.plugins.otp_totp.models import TOTPDevice
from django_ratelimit.decorators import ratelimit

from accounts.forms import LoginForm, MFASetupForm, MFAVerifyForm
from accounts.models import CustomUser
from audit.models import AuditAction
from audit.service import log_security_event


@ratelimit(key='ip', rate='15/m', block=True)
@require_http_methods(["GET", "POST"])
def login_view(request):
    """
    Step 1 of authentication: verifies username and Argon2id password hash.
    Protected by django-axes for account lockout and django-ratelimit.
    If MFA is enabled for the account, the session is kept unverified and
    redirected to the TOTP challenge step.
    """
    if request.user.is_authenticated and request.session.get('mfa_verified', False):
        return redirect('case_list')

    if request.method == 'POST':
        form = LoginForm(request.POST, request=request)
        if form.is_valid():
            user = form.cleaned_data['user']
            user.reset_failed_logins()

            if user.is_mfa_enabled:
                # Store pending MFA state in session
                request.session['mfa_user_id'] = str(user.id)
                request.session['mfa_verified'] = False
                log_security_event(
                    action=AuditAction.LOGIN_SUCCESS,
                    actor=user,
                    request=request,
                    details={'stage': 'primary_credentials_verified_mfa_pending'}
                )
                return redirect('mfa_verify')
            else:
                # Login without MFA, but prompt to setup
                auth_login(request, user)
                request.session['mfa_verified'] = True
                log_security_event(
                    action=AuditAction.LOGIN_SUCCESS,
                    actor=user,
                    request=request,
                    details={'stage': 'full_login_mfa_disabled'}
                )
                messages.warning(
                    request,
                    "Security Notice: Multi-Factor Authentication (MFA) is not yet active on your account. "
                    "Please configure an authenticator app to comply with firm policy."
                )
                return redirect('case_list')
        else:
            username_attempt = request.POST.get('username', '')
            log_security_event(
                action=AuditAction.LOGIN_FAILED,
                request=request,
                details={'attempted_username': username_attempt}
            )
    else:
        form = LoginForm()

    return render(request, 'accounts/login.html', {'form': form})


@ratelimit(key='ip', rate='15/m', block=True)
@require_http_methods(["GET", "POST"])
def mfa_verify_view(request):
    """
    Step 2 of authentication: verifies RFC 6238 TOTP token using django-otp.
    Grants elevated session rights upon successful verification.
    """
    mfa_user_id = request.session.get('mfa_user_id')
    user = None

    if mfa_user_id:
        try:
            user = CustomUser.objects.get(id=mfa_user_id)
        except CustomUser.DoesNotExist:
            user = None
    elif request.user.is_authenticated:
        user = request.user

    if not user:
        messages.error(request, "Authentication session expired. Please log in again.")
        return redirect('login')

    if request.method == 'POST':
        form = MFAVerifyForm(request.POST)
        if form.is_valid():
            token = form.cleaned_data['token']
            device = TOTPDevice.objects.filter(user=user, confirmed=True).first()
            is_valid_token = False

            if device and device.verify_token(token):
                is_valid_token = True
                otp_login(request, device)
            elif user.verify_totp(token):
                is_valid_token = True
                # Ensure a confirmed django-otp TOTPDevice exists
                dev, _ = TOTPDevice.objects.get_or_create(user=user, name='default')
                dev.confirmed = True
                dev.save()
                otp_login(request, dev)

            if is_valid_token:
                if not request.user.is_authenticated:
                    auth_login(request, user, backend='django.contrib.auth.backends.ModelBackend')

                request.session['mfa_verified'] = True
                request.session.pop('mfa_user_id', None)

                log_security_event(
                    action=AuditAction.MFA_VERIFIED,
                    actor=user,
                    request=request,
                    details={'result': 'success', 'engine': 'django_otp'}
                )
                messages.success(request, f"Welcome back, {user.get_full_name() or user.username}. Session verified.")
                next_url = request.GET.get('next')
                return redirect(next_url if next_url and next_url.startswith('/') else 'case_list')
            else:
                user.record_failed_login()
                log_security_event(
                    action=AuditAction.MFA_FAILED,
                    actor=user,
                    request=request,
                    details={'result': 'invalid_token'}
                )
                form.add_error('token', "Invalid or expired verification code. Please check your authenticator clock.")
    else:
        form = MFAVerifyForm()

    return render(request, 'accounts/mfa_verify.html', {'form': form, 'user_target': user})


@login_required
@require_http_methods(["GET", "POST"])
def mfa_setup_view(request):
    """
    Enrolls user into TOTP Multi-Factor Authentication via django-otp.
    Generates a secure Base32 secret and an inline SVG QR code.
    """
    user = request.user
    if not user.totp_secret:
        user.generate_totp_secret()

    device, _ = TOTPDevice.objects.get_or_create(user=user, name='default', defaults={'confirmed': False})

    if request.method == 'POST':
        form = MFASetupForm(request.POST)
        if form.is_valid():
            token = form.cleaned_data['token']
            if device.verify_token(token) or user.verify_totp(token):
                device.confirmed = True
                device.save()
                otp_login(request, device)

                user.is_mfa_enabled = True
                user.save(update_fields=['is_mfa_enabled'])
                request.session['mfa_verified'] = True
                log_security_event(
                    action=AuditAction.MFA_SETUP,
                    actor=user,
                    request=request,
                    details={'status': 'enabled', 'engine': 'django_otp'}
                )
                messages.success(request, "Multi-Factor Authentication has been successfully activated for your account.")
                return redirect('case_list')
            else:
                form.add_error('token', "Verification code incorrect. Please verify and try again.")
    else:
        form = MFASetupForm()

    # Generate QR Code SVG in-memory (no external network CDNs to satisfy strict CSP)
    uri = user.get_totp_uri()
    img = qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage)
    stream = io.BytesIO()
    img.save(stream)
    qr_svg = stream.getvalue().decode('utf-8')

    context = {
        'form': form,
        'totp_secret': user.totp_secret,
        'qr_svg': qr_svg,
    }
    return render(request, 'accounts/mfa_setup.html', context)


@require_http_methods(["GET", "POST"])
def logout_view(request):
    """
    Terminates the authenticated session, invalidating cookies and recording an audit event.
    """
    if request.user.is_authenticated:
        log_security_event(
            action=AuditAction.LOGOUT,
            actor=request.user,
            request=request,
            details={'reason': 'user_requested'}
        )
    auth_logout(request)
    messages.info(request, "You have been securely signed out.")
    return redirect('login')
