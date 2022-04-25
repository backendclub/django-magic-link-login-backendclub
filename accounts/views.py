import base64
from urllib.parse import urlencode, unquote_plus
from django.core import signing
from django.core.mail import send_mail
from django.urls import reverse
from django.http import HttpResponse, HttpRequest
from django.contrib.auth import login, logout, get_user_model
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect, render
from django.views.decorators.http import require_GET
from django.utils import timezone
from django.utils.crypto import get_random_string


User = get_user_model()


@require_GET
def magic_link_login(request):
    token = request.GET.get("token")
    if not token:
        # Go back to main page; alternatively show an error page
        return redirect("home")

    data = signing.loads(token, max_age=3600)
    email = data.get("email")
    if not email:
        return redirect("home")

    user = User.objects.filter(username=email, is_active=True).first()
    if not user:
        # user does not exist or is inactive
        return redirect("home")

    # validate token and check for expiry; we want to make sure
    # it's only been generated since the last login
    if user.last_login:
        delta = timezone.now() - user.last_login
        try:
            data = signing.loads(token, max_age=delta)
        except signing.SignatureExpired:
            # signature expired, redirect to main page or show error page.
            return redirect("home")

    login_state = data.get("login_state")
    session_login_state = request.session.get("login_state")

    if not login_state or not session_login_state:
        return redirect("home")

    if login_state != session_login_state:
        return redirect("home")

    # Everything checks out, log the user in and redirect to dashboard!
    login(request, user)
    return redirect("dashboard")


@login_required(login_url="/", redirect_field_name=None)
@require_GET
def dashboard(request):
    return render(request, 'dashboard.html', {})


def home(request: HttpRequest):
    if request.POST:
        email = request.POST.get("email")
        if user := User.objects.filter(username=email, is_active=True).first():
            random_string = get_random_string(16)
            request.session["login_state"] = random_string
            token = signing.dumps({"email": email, "login_state": random_string})
            qs = urlencode({"token": token})

            magic_link = request.build_absolute_uri(
                location=reverse("auth-magic-link"),
            ) + f"?{qs}"

            send_mail(
                "Login link",
                f'Click <a href="{magic_link}">here</a> to login',
                'from@example.com',
                [email],
                fail_silently=True,
            )
        return redirect("home")
    return render(request, 'home.html', {})


def logout_view(request):
    logout(request)
    return redirect("home")
