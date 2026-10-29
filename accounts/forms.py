"""
CaseVault Authentication Forms
Organization: Northbridge Cyber Response
Module: CYS22301 Software and Platform Security (Level 6)
"""

from django import forms
from django.contrib.auth import authenticate
from django.core.exceptions import ValidationError
from accounts.models import CustomUser


class LoginForm(forms.Form):
    username = forms.CharField(
        max_length=150,
        widget=forms.TextInput(attrs={
            'class': 'form-input',
            'placeholder': 'Investigator username',
            'autocomplete': 'username',
            'required': True,
        })
    )
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-input',
            'placeholder': 'Password',
            'autocomplete': 'current-password',
            'required': True,
        })
    )

    def clean(self):
        cleaned_data = super().clean()
        username = cleaned_data.get('username')
        password = cleaned_data.get('password')

        if username and password:
            try:
                user = CustomUser.objects.get(username=username)
            except CustomUser.DoesNotExist:
                user = None

            if user and user.is_account_locked():
                raise ValidationError(
                    "This account is temporarily locked due to excessive failed attempts. "
                    "Please wait 15 minutes before retrying or contact the administrator."
                )

            auth_user = authenticate(username=username, password=password)
            if auth_user is None:
                if user:
                    user.record_failed_login()
                raise ValidationError("Invalid username or password.")
            
            cleaned_data['user'] = auth_user
        return cleaned_data


class MFAVerifyForm(forms.Form):
    token = forms.CharField(
        max_length=8,
        min_length=6,
        widget=forms.TextInput(attrs={
            'class': 'form-input text-center text-2xl tracking-widest',
            'placeholder': '123456',
            'autocomplete': 'one-time-code',
            'inputmode': 'numeric',
            'pattern': '[0-9]*',
            'autofocus': True,
            'required': True,
        }),
        help_text="Enter the 6-digit code from your authenticator application."
    )


class MFASetupForm(forms.Form):
    token = forms.CharField(
        max_length=8,
        min_length=6,
        widget=forms.TextInput(attrs={
            'class': 'form-input text-center text-xl tracking-widest',
            'placeholder': '123456',
            'autocomplete': 'one-time-code',
            'inputmode': 'numeric',
            'required': True,
        }),
        help_text="Verify your authenticator app by entering the generated 6-digit code."
    )
