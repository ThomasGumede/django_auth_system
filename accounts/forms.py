from django import forms
from .models import CustomUser
from django.contrib.auth.forms import (AuthenticationForm, PasswordResetForm,
                                       SetPasswordForm)

class UserLoginForm(AuthenticationForm):

    username = forms.EmailField(widget=forms.EmailInput(
        attrs={'placeholder': 'email', 'id': 'login-email'}))
    password = forms.CharField(widget=forms.PasswordInput(
        attrs={
            'class': 'bg-gray-50 border border-gray-300 text-gray-900 sm:text-sm rounded-lg focus:ring-blue-500 focus:border-blue-500 block w-full p-2.5',
            'placeholder': 'Password',
            'id': 'login-pwd',
        }
    ))

class RegistrationForm(forms.ModelForm):
    """
    Registration Form - create new user using username, email and password
    """

    error_messages = {
        'password_mismatch': 'Passwords doesn\'t match',
        'username_exists': 'This username already exists, please choose another username',
        'email_exists': 'This email already exists, please choose another email'
    }


    username = forms.CharField(label='Enter Username', max_length=50, help_text='Required', widget=forms.TextInput(attrs={'id': 'form-username'}))
    email = forms.EmailField(label='Enter Email address', max_length=100, help_text='Required', error_messages={'required': 'Sorry, you will need an email'}, widget=forms.EmailInput(
        attrs={'placeholder': 'email', 'id': 'form-email'}))
    phone = forms.CharField(label='Enter Phone number', min_length=4, max_length=50, help_text='Required', widget=forms.TextInput(attrs={'id': 'form-phone'}))
    password = forms.CharField(label='Password', widget=forms.PasswordInput(attrs={'id': 'form-password'}), strip=False)
    password2 = forms.CharField(label='Confirm password', widget=forms.PasswordInput(attrs={'id': 'form-password2'}), strip=False)

    class Meta:
        model = CustomUser
        fields = ['username', 'email', 'phone', 'password', 'password2']

    def clean_username(self):
        
        """
        Check if the username already exists
        """
        username = self.cleaned_data['username']
        if CustomUser.objects.filter(username=username).exists():
            raise forms.ValidationError(self.error_messages['username_exists'])
        return username

    def clean_email(self):

        """
        Checks if the email already exists
        """
        email = self.cleaned_data['email']
        if CustomUser.objects.filter(email=email).exists():
            raise forms.ValidationError(self.error_messages['email_exists'])

        return email

    def clean_password2(self):
        password1 = self.cleaned_data.get("password")
        password2 = self.cleaned_data.get("password2")
        if password1 and password2 and password1 != password2:
            raise forms.ValidationError(
                self.error_messages['password_mismatch'],
                code='password_mismatch',
            )
        return password2

    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data["password"])
        if commit:
            user.save()
        return user

class AccountActivationForm(forms.Form):
    email = forms.EmailField(label='Enter Email address', max_length=254, widget=forms.TextInput(
        attrs={'placeholder': 'Email', 'id': 'form-email'}))

    def clean_email(self):
        email = self.cleaned_data['email']
        
        if not CustomUser.objects.filter(email=email).exists():
            raise forms.ValidationError(
                'Unfortunatley we can not find this email address')
        return email

class PwdResetForm(PasswordResetForm):
    """
    Custom password reset form
    """

    email = forms.EmailField(label='Enter Email address', max_length=254, widget=forms.TextInput(
        attrs={'placeholder': 'Email', 'id': 'form-email'}))

    def clean_email(self):
        email = self.cleaned_data['email']
        
        if not CustomUser.objects.filter(email=email).exists():
            raise forms.ValidationError(
                'Unfortunatley we can not find this email address')
        return email

class PwdResetConfirmForm(SetPasswordForm):
    new_password1 = forms.CharField(
        label='New password', widget=forms.PasswordInput(
            attrs={'placeholder': 'New Password', 'id': 'form-password1'}))
    new_password2 = forms.CharField(
        label='Confirm new password', widget=forms.PasswordInput(
            attrs={'placeholder': 'Confirm New Password', 'id': 'form-password2'}))

class UpdateForm(forms.ModelForm):

    username = forms.CharField(label='username', max_length=50, widget=forms.TextInput(attrs={'placeholder': 'Username', 'id': 'form-username', 'readonly': 'readonly'}))
    email = forms.EmailField(label='Account email (can not be changed)', max_length=200, widget=forms.TextInput(attrs={'placeholder': 'email', 'id': 'form-email', 'readonly': 'readonly'}))
    first_name = forms.CharField(label='First name', max_length=200, widget=forms.TextInput(attrs={'placeholder': 'First name', 'id': 'form-firstname'}))
    last_name = forms.CharField(label='Last name', max_length=200, widget=forms.TextInput(attrs={'placeholder': 'Last name', 'id': 'form-lastname'}))
    profile_pic = forms.ImageField()
    bio = forms.Textarea()


        
    class Meta:
        model = CustomUser
        fields = ['username', 'email', 'first_name', 'last_name', 'profile_pic', 'bio']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['profile_pic'].widget.attrs.update({
            'class': 'cursor-pointer absolute block opacity-0 pin-r pin-t'
        })
        self.fields['bio'].widget.attrs.update({
            'class': 'bg-gray-50 border border-gray-300 text-gray-900 sm:text-sm rounded-lg focus:ring-blue-500 focus:border-blue-500 block w-full p-2.5'
        })
