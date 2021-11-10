from django.urls.base import reverse_lazy
from .forms import RegistrationForm, UpdateForm, PwdResetConfirmForm, AccountActivationForm
from .tokens import account_activation_token
from .models import CustomUser
from django.shortcuts import render, redirect
from django.views.generic import View
from django.contrib import messages
from django.contrib.sites.shortcuts import get_current_site
from django.utils.encoding import force_bytes, force_text
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.template.loader import render_to_string
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.views import PasswordResetConfirmView
from django.contrib.auth import login


class HomeView(LoginRequiredMixin, View):
    template_name = 'home/home.html'

    def get(self, request):
        user = request.user

        return render(request, self.template_name, {'user': user})

class SignUpView(View):
    form_class = RegistrationForm
    template_name = 'account/registration/signup.html'

    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            return redirect('accounts:home')
        return super().dispatch(request, *args, **kwargs)

    def get(self, request):
        form = self.form_class()
        return render(request, self.template_name, {'form': form})

    def post(self, request):
        form = self.form_class(request.POST)

        if form.is_valid():
            user = form.save(commit=False)
            user.save()

            current_site = get_current_site(request)
            subject = 'Activate Your MySite Account'
            message = render_to_string('account/emails/account_activation_email.html', {
                'user': user,
                'domain': current_site.domain,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': account_activation_token.make_token(user),
            })
            user.email_user(subject, message)

            return render(request, "account/registration/register_email_confirm.html", {"form": form})

        else:
            return render(request, self.template_name, {'form': form})

class ResendAccountActivationEmail(View):
    form_class = AccountActivationForm
    template_name = 'account/registration/re_activate_account.html'

    def get(self, request):
        form = self.form_class()
        return render(request, self.template_name, {'form': form})

    def post(self, request):
        form = self.form_class(request.POST)

        if form.is_valid():
            cd = form.cleaned_data['email']
            user = CustomUser.objects.get(email=cd)

            if not  CustomUser.objects.filter(email=cd).exists():
                messages.error(request, 'This email doesn\'t exists, please try again with valid email or signup new account')
                return render(request, self.template_name, {'form': form})
            
            if  CustomUser.objects.filter(email=cd).exists() and  user.is_active == True:
                messages.warning(request, 'Sorry this account is already verified, please Login')
                return redirect('accounts:login')


            current_site = get_current_site(request)
            subject = 'Activate Your MySite Account'
            message = render_to_string('account/emails/account_activation_email.html', {
                'user': user,
                'domain': current_site.domain,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': account_activation_token.make_token(user),
            })
            user.email_user(subject, message)

            return render(request, "account/registration/register_email_confirm.html", {"form": form})

class AccountActivationView(View):
    def get(self, request, uidb64, token, *args, **kwargs):
        try:
            uid = force_text(urlsafe_base64_decode(uidb64))
            user = CustomUser.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, CustomUser.DoesNotExist):
            user = None
        
        if user is not None and account_activation_token.check_token(user, token):
            user.is_active = True
            user.save()
            login(request, user)
            messages.success(request, ('Your account have been confirmed.'))
            return redirect('accounts:home')
        else:
            return render(request, "account/registration/activation_invalid.html")

class AccountUpdate(LoginRequiredMixin, View):
    form_class = UpdateForm
    template_name = 'account/update_account.html'

    def get(self, request):
        form = self.form_class(instance=request.user)
        return render(request, self.template_name, {'form': form})

    def post(self, request):
        form = self.form_class(instance=request.user, data=request.POST, files=request.FILES)
        if form.is_valid():
            form.save()

            messages.success(request, ('Profile updated successfully'))
            return redirect('accounts:home')

        messages.error(request, ('Something went wrong, please provide valid details'))
        return render(request, self.template_name, {'form': form})

class PwdResetConfirmView(PasswordResetConfirmView):
    template_name = 'account/password/password_reset_confirm.html'
    success_url = reverse_lazy('accounts:password_reset_complete')
    form_class=PwdResetConfirmForm