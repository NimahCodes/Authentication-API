from django.urls import path
from .views import RegisterView, VerifyEmail, LoginAPIView, ForgetPasswordAPI, ResetPassword, PasswordTOkenCheckAPI


urlpatterns = [
    path("register/", RegisterView.as_view(), name="register"),
    path('email-verify/', VerifyEmail.as_view(), name="email-verify"),
    path('login/', LoginAPIView.as_view(), name="login"),
    path('forgot-password/', ForgetPasswordAPI.as_view(), name="forgot-password"),
    path('password-auth-token/<uidb64>/<token>/', PasswordTOkenCheckAPI.as_view(), name='password-auth-token'),
    path('reset-password/', ResetPassword.as_view(), name="reset-password"),

]
