from django.shortcuts import render, redirect
import uuid
import requests
import msal
from qrcode.settings import SCOPE, AUTHORITY, CLIENT_ID, CLIENT_SECRET, AUTHORITY
from django.urls import reverse



def index(request):
    print("masukkkkk")
    if not request.session.get("user"):
        return redirect(reverse("login"))
    context = {'user':request.session["user"], 'version':msal.__version__ }
    return render(request, 'index.html', context)

def login(request):
    print("masukkk")
    request.session["state"] = str(uuid.uuid4())
    auth_url = _build_auth_url(scopes=SCOPE, state=request.session["state"])
    print("cek", auth_url)
    context = {'auth_url':auth_url, 'version':msal.__version__}
    return render(request, "login.html", context)

def authorized(request, *args, **kwargs):
    print("cekkk")
    if request.GET.get('state', None) != request.session.get("state"):
        print("1")
        return redirect(reverse("index"))  # No-OP. Goes back to Index page
    if "error" in request.GET:  # Authentication/Authorization failure
        print("2")
        context = {'result':request.args}
        return render(request, "auth_error.html", context)
    if request.GET.get('code', None):
        print("3")
        cache = _load_cache(request)
        result = _build_msal_app(cache=cache).acquire_token_by_authorization_code(
            request.GET.get('code', None),
            scopes=SCOPE,  # Misspelled scope would cause an HTTP 400 error here
            redirect_uri='http://localhost:5000/getAToken')
        print("4")
        if "error" in result:
            print("5")
            context = {"result":result}
            return render(request, "auth_error.html", context)
        request.session["user"] = result.get("id_token_claims")
        _save_cache(cache, request)
    return redirect(reverse("index"))


def logout(request):
    request.session.clear()  # Wipe out user and its token cache from session
    return redirect(  # Also logout from your tenant's web session
        AUTHORITY + "/oauth2/v2.0/logout" +
        "?post_logout_redirect_uri=" + 'http://localhost:5000/getAToken')

# @app.route("/graphcall")
# def graphcall():
#     token = _get_token_from_cache(app_config.SCOPE)
#     if not token:
#         return redirect(reverse("login"))
#     graph_data = requests.get(  # Use token to call downstream service
#         app_config.ENDPOINT,
#         headers={'Authorization': 'Bearer ' + token['access_token']},
#         ).json()
#     return render('display.html', result=graph_data)


def _load_cache(request):
    cache = msal.SerializableTokenCache()
    if request.session.get("token_cache"):
        cache.deserialize(request.session["token_cache"])
    return cache

def _save_cache(cache, request):
    if cache.has_state_changed:
        request.session["token_cache"] = cache.serialize()

def _build_msal_app(cache=None, authority=None):
    return msal.ConfidentialClientApplication(
        CLIENT_ID, authority=authority or AUTHORITY,
        client_credential=CLIENT_SECRET, token_cache=cache)

def _build_auth_url(authority=None, scopes=None, state=None):
    print("masukkk3k")
    return _build_msal_app(authority=authority).get_authorization_request_url(
        scopes or [],
        state=state or str(uuid.uuid4()),
        redirect_uri='http://localhost:5000/getAToken')

# def _get_token_from_cache(scope=None):
#     cache = _load_cache()  # This web app maintains one cache per session
#     cca = _build_msal_app(cache=cache)
#     accounts = cca.get_accounts()
#     if accounts:  # So all account(s) belong to the current signed-in user
#         result = cca.acquire_token_silent(scope, account=accounts[0])
#         _save_cache(cache)
#         return result

# Create your views here.
# def check_auth(request):
#     return render(request, 'index.html')