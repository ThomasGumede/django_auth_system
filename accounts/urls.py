from django.urls import path, reverse_lazy
from .forms import UserLoginForm, PwdResetForm
from .views import HomeView, SignUpView, AccountActivationView, AccountUpdate, PwdResetConfirmView, ResendAccountActivationEmail
from django.contrib.auth.views import (
    LoginView, 
    LogoutView, 
    PasswordResetView,  
    PasswordResetCompleteView, 
    PasswordResetDoneView
)

app_name = 'accounts'

urlpatterns = [
    path('', LoginView.as_view(template_name='account/login.html', form_class=UserLoginForm, redirect_authenticated_user=True), name='login'),
    path('logout', LogoutView.as_view(next_page="accounts:login"), name='logout'),
    path('signup', SignUpView.as_view(), name='signup'),
    path('dashboard', HomeView.as_view(), name='home'),
    path('re_activate', ResendAccountActivationEmail.as_view(), name='re_activate_account'),
    path('dashboad/update', AccountUpdate.as_view(), name='update_account'),
    path('activate/<uidb64>/<token>', AccountActivationView.as_view(), name='activate'),
    
    
    path(
        'password/reset_password', 
        PasswordResetView.as_view(
            template_name='account/password/password_reset_form.html', 
            form_class=PwdResetForm, 
            success_url='pwd_reset_email_sent/',
            email_template_name="account/emails/password_reset_email.html"
            ), 

        name='password_reset'),

    path(
        'password/pwd_reset_email_sent/',
        PasswordResetDoneView.as_view(
            template_name='account/password/password_reset_done.html'
        ),
        name='pwd_email_sent_confirm'
    ),

    path(
        'password/<uidb64>/<token>',
        PwdResetConfirmView.as_view(),
        name='pwd_reset_confirm'
    ),

    path(
        'password/pwd_reset_complete',
        PasswordResetCompleteView.as_view(
            template_name='account/password/password_reset_complete.html'
        ),
        name='password_reset_complete'
    )
    
]
