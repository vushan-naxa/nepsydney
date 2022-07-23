from allauth.account.adapter import get_adapter
from allauth.socialaccount.providers.facebook.views import \
    FacebookOAuth2Adapter
from allauth.socialaccount.providers.google.views import GoogleOAuth2Adapter
from dj_rest_auth.app_settings import (JWTSerializer,
                                       JWTSerializerWithExpiration,
                                       LoginSerializer, TokenSerializer,
                                       create_token)
from django.conf import settings
from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.models import User
from django.core.exceptions import ImproperlyConfigured
from django.core.mail import send_mail
from django.db.models import Q
from django.http import HttpResponse
from django.shortcuts import render
from django.template.loader import render_to_string
from django.utils.decorators import method_decorator
from django.utils.encoding import force_bytes, force_str
from django.utils.html import strip_tags
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.module_loading import import_string
from django.views.decorators.debug import sensitive_post_parameters
from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.decorators import api_view, permission_classes
from rest_framework.generics import GenericAPIView
from rest_framework.mixins import CreateModelMixin
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.views import APIView, Response
from rest_framework.viewsets import GenericViewSet, ModelViewSet

from .models import UserProfile
from .serializers import (SocialLoginSerializer, UserProfileSerializer,
                          UserSerializer)
from .utils import account_activation_token

serializers = getattr(settings, 'REST_AUTH_SERIALIZERS', {})


sensitive_post_parameters_m = method_decorator(
    sensitive_post_parameters(
        'password', 'old_password', 'new_password1', 'new_password2',
    ),
)


def get_token_model():
    default_model = 'rest_framework.authtoken.models.Token'
    import_path = getattr(settings, 'REST_AUTH_TOKEN_MODEL', default_model)
    session_login = getattr(settings, 'REST_SESSION_LOGIN', True)
    use_jwt = getattr(settings, 'REST_USE_JWT', False)

    if not any((session_login, import_path, use_jwt)):
        raise ImproperlyConfigured(
            'No authentication is configured for rest auth. You must enable one or '
            'more of `REST_AUTH_TOKEN_MODEL`, `REST_USE_JWT` or `REST_SESSION_LOGIN`'
        )
    if (
        import_path == default_model
        and 'rest_framework.authtoken' not in settings.INSTALLED_APPS
    ):
        raise ImproperlyConfigured(
            'You must include `rest_framework.authtoken` in INSTALLED_APPS '
            'or set REST_AUTH_TOKEN_MODEL to None'
        )
    return import_string(import_path) if import_path else None


TokenModel = get_token_model()


class UserRegisterViewSet(GenericViewSet, CreateModelMixin):
    serializer_class = UserSerializer

    def create(self, request):
        try:
            if UserProfile.objects.filter(user__email=request.data.get("email")).exists():
                return Response({"message": "Email is already registered"}, status=400)
            if UserProfile.objects.filter(user__username=request.data.get("username")).exists():
                return Response({"message": "Username is already registered"}, status=400)
            serializer = self.serializer_class(data=request.data)
            if serializer.is_valid():
                user = serializer.save(is_active=False)
                user.set_password(serializer.validated_data["password"])
                user.save()
                return Response({"message": "User successfully registered. Please check your mail and verify your account"},
                                status=status.HTTP_201_CREATED)
            else:
                return Response({"message": str(serializer.errors)}, status=400)
        except Exception as error:
            return Response({"message": str(error)}, status=400)

    def __str__(self):
        return "UserRegisterViewSet"


class UserSignIn(APIView):
    def post(self, request, *args, **kwargs):
        username = request.data.get("username")
        password = request.data.get("password")
        if User.objects.filter(Q(username=username) | Q(email=username)).exists():
            user = User.objects.filter(
                Q(username=username) | Q(email=username))[0]
            if user.check_password(password):
                if user.is_active:
                    token, created = Token.objects.get_or_create(user=user)
                    return Response({
                        'token': token.key,
                        'user_id': user.pk,
                        'email': user.email,
                        'username': user.username})
                return Response({"message": "Unverified account .Please check your email and verify your account."}, status=400)
            return Response({"message": "Invalid password"}, status=403)
        return Response({"message": "User does not exist."}, status=400)


def activate_user(request, uidb64, token):
    User = get_user_model()
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    if user is not None and account_activation_token.check_token(user, token):
        user.is_active = True
        user.save()

        # creating user profile
        profile = UserProfile.objects.create(
            user=user, email=user.email)
        first_name, last_name, email, middle_name = user.first_name, user.last_name, user.email, ''
        if first_name and last_name:
            profile.first_name = first_name
            profile.last_name = last_name
            profile.middle_name = middle_name
            profile.email = email
            profile.save()
        return HttpResponse('Thank you for your email confirmation. Now you can login your account.')
    else:
        return HttpResponse('Activation link is invalid!')


class UserProfileViewSet(ModelViewSet):
    permission_classes = [IsAuthenticated]
    queryset = UserProfile.objects.order_by('-id')
    serializer_class = UserProfileSerializer
    http_method_names = ['get', 'post', 'patch']

    def get_queryset(self):
        queryset = UserProfile.objects.order_by('-id')
        id = self.request.query_params.get('id', None)
        if id:
            queryset = UserProfile.objects.filter(user=self.request.user)
        return queryset


@api_view(['POST'])
@permission_classes((IsAuthenticated,))
def change_password(request):
    old_password = request.data.get('old_password', None)
    new_password = request.data.get('new_password', None)
    confirm_password = request.data.get('confirm_password', None)
    user = authenticate(
        username=request.user.username, password=old_password)

    if user is not None:
        if new_password == confirm_password:
            user.set_password(new_password)
            user.save()
            return Response(status=status.HTTP_201_CREATED, data={'Message': 'Password Successfuly Updated.'})
        else:
            return Response(status=status.HTTP_400_BAD_REQUEST, data={'Error': 'New and Confirm passwords do not match.'})

    else:
        return Response(status=status.HTTP_400_BAD_REQUEST, data={'Error': 'Incorrect old password'})


@api_view(['POST'])
@permission_classes((IsAuthenticated,))
def forgot_password(request):
    '''
    This function allows user to request passowrsd reset
    and sends password reset email with uid and token
    for validating in next funtiom.
    '''
    email = request.data.get('email', None)
    if User.objects.filter(email=email).exists():
        user = User.objects.get(email=email)
        username = user.username if user.username else email.split(
            '@')[0]

        # password reset link email
        current_site = settings.BACKEND_URL
        email_subject = 'Reset Password for Naxa App'
        template = 'forgot_password_email_template.html'

        email_data = {
            'user': username.title(),
            'domain': current_site,
            'uid': urlsafe_base64_encode(force_bytes(user.pk)),
            'token': account_activation_token.make_token(user),

        }

        mail_to = str(request.data['email'])
        html_message = render_to_string(
            template, email_data)
        email_message = strip_tags(html_message)

        email_res = send_mail(email_subject,
                              email_message, settings.EMAIL_HOST_USER, [email, ], html_message=html_message, fail_silently=False)
        email_response = "We have sent an link to reset your password. Please check your email" if email_res else "Could not send and email. Please try again later"
        return Response({'Message': email_response}, status=status.HTTP_200_OK)
    else:
        return Response({'Message': 'User does not exists with this email.'}, status=status.HTTP_404_NOT_FOUND)


def reset_passoword(request, uidb64, token):
    '''
    This function checks if passoword change request is
    valid. And resets password if it is valid.
    '''
    User = get_user_model()
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    if user is not None and account_activation_token.check_token(user, token):
        if request.method == "POST":
            new_password = request.POST.get('new_password')
            confirm_password = request.POST.get('confirm_password')

            if new_password == confirm_password:
                user.set_password(new_password)
                user.save()
                return render(
                    request, 'forgot_password_confirm_password.html', {'action': 'success', 'uidb64': uidb64, 'token': token})
            else:
                return render(
                    request, 'forgot_password_confirm_password.html', {'action': 'mismatch', 'uidb64': uidb64, 'token': token})
        else:
            return render(
                request, 'forgot_password_confirm_password.html', {'action': 'confirming', 'uidb64': uidb64, 'token': token})
    else:
        return render(
            request, 'forgot_password_confirm_password.html', {'action': 'invalid_link', 'uidb64': uidb64, 'token': token})


# views for social login (facebook and google), remove all code below this if you don't need social login
class LoginView(GenericAPIView):
    """
    Check the credentials and return the REST Token
    if the credentials are valid and authenticated.
    Calls Django Auth login method to register User ID
    in Django session framework
    Accept the following POST parameters: username, password
    Return the REST Framework Token Object's key.
    """
    permission_classes = (AllowAny,)
    serializer_class = LoginSerializer
    throttle_scope = 'dj_rest_auth'

    user = None
    access_token = None
    token = None

    @sensitive_post_parameters_m
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    def process_login(self):
        django_login(self.request, self.user)

    def get_response_serializer(self):
        if getattr(settings, 'REST_USE_JWT', False):

            if getattr(settings, 'JWT_AUTH_RETURN_EXPIRATION', False):
                response_serializer = JWTSerializerWithExpiration
            else:
                response_serializer = JWTSerializer

        else:
            response_serializer = TokenSerializer
        return response_serializer

    def login(self):
        self.user = self.serializer.validated_data['user']
        token_model = get_token_model()

        if getattr(settings, 'REST_USE_JWT', False):
            self.access_token, self.refresh_token = jwt_encode(self.user)
        elif token_model:
            self.token = create_token(token_model, self.user, self.serializer)

        if getattr(settings, 'REST_SESSION_LOGIN', True):
            self.process_login()

    def get_response(self):
        serializer_class = self.get_response_serializer()

        if getattr(settings, 'REST_USE_JWT', False):
            from rest_framework_simplejwt.settings import \
                api_settings as jwt_settings
            access_token_expiration = (
                timezone.now() + jwt_settings.ACCESS_TOKEN_LIFETIME)
            refresh_token_expiration = (
                timezone.now() + jwt_settings.REFRESH_TOKEN_LIFETIME)
            return_expiration_times = getattr(
                settings, 'JWT_AUTH_RETURN_EXPIRATION', False)

            data = {
                'user': self.user,
                'access_token': self.access_token,
                'refresh_token': self.refresh_token,
            }

            if return_expiration_times:
                data['access_token_expiration'] = access_token_expiration
                data['refresh_token_expiration'] = refresh_token_expiration

            serializer = serializer_class(
                instance=data,
                context=self.get_serializer_context(),
            )
        elif self.token:
            serializer = serializer_class(
                instance=self.token,
                context=self.get_serializer_context(),
            )
        else:
            return Response(status=status.HTTP_204_NO_CONTENT)

        response = Response(serializer.data, status=status.HTTP_200_OK)
        if getattr(settings, 'REST_USE_JWT', False):
            from .jwt_auth import set_jwt_cookies
            set_jwt_cookies(response, self.access_token, self.refresh_token)
        return response

    def post(self, request, *args, **kwargs):
        self.request = request
        self.serializer = self.get_serializer(data=self.request.data)
        self.serializer.is_valid(raise_exception=True)

        self.login()
        return self.get_response()


class SocialLoginView(LoginView):
    serializer_class = SocialLoginSerializer

    def process_login(self):
        get_adapter(self.request).login(self.request, self.user)


class CustomFacebookLoginView(SocialLoginView):
    adapter_class = FacebookOAuth2Adapter


class CustomGoogleLoginView(SocialLoginView):

    adapter_class = GoogleOAuth2Adapter
