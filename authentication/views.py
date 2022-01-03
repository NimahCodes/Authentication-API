from django.shortcuts import render
from jwt.exceptions import DecodeError
from rest_framework import exceptions, generics, serializers, status
import rest_framework
from .serializers import RegisterSerializer, LoginSerializer, ForgetPasswordSerializer, ResetPasswordSerializer
from rest_framework.response import Response
from .models import User
from rest_framework_simplejwt.tokens import RefreshToken
from .utils import Util
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from .generate_otp import generateOTP
import jwt
from django.conf import settings
from rest_framework.views import APIView
from rest_framework import permissions
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.urls import reverse
from django.utils.encoding import smart_bytes, DjangoUnicodeDecodeError
from django.contrib.auth import get_user_model, logout
# from rest_framework_swagger.views import get_swagger_view
# from django.conf.urls import url
# from django.conf.urls import url

# schema_view = get_swagger_view(title = 'Authentication API')

# urlpatterns = [
    # url(r'^$', schema_view),
    
# ]






class RegisterView(generics.GenericAPIView):

    serializer_class = RegisterSerializer
    queryset = User.objects.all()


    def post(self, request):
        input_data = request.data
        serializer = self.serializer_class(data=input_data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        user_data = serializer.data
        email = user_data['email']
        user = User.objects.get(email=email)

        token = RefreshToken.for_user(user).access_token
        print(token)
        OTP = generateOTP()

        current_site = get_current_site(request).domain
        relativeLink = reverse('email-verify')

        absurl = 'http://'+current_site+relativeLink+"?token="+str(token)
        email_body = 'Hi '+user.username+'Use link below to verify your email \n'+'This is your OTP'+ ' ' + OTP + absurl
        data = {'email_body': email_body,
                'email_subject': 'Verify your email', "to_email": [email]}
        Util.send_email(data)

        return Response(user_data, status=status.HTTP_201_CREATED)



class VerifyEmail(APIView):
    def get(self, request):
        token = request.GET.get('token')
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            user = User.objects.get(id=payload['user_id'])
            print('user', user)
            if not user.is_verified:
                user.is_verified = True
                user.is_active = True
            
                user.save()
            return Response({'email':'successfuly activated'}, status=status.HTTP_200_OK)
        
        except jwt.ExpiredSignatureError:
            return Response({'error':'Activation Expired expired'}, status=status.HTTP_400_BAD_REQUEST)
        
        except jwt.exceptions.DecodeError:
            return Response({'error':'invalid token'}, status=status.HTTP_400_BAD_REQUEST)


class LoginAPIView(generics.GenericAPIView):
    serializer_class = LoginSerializer
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)    
        return Response(serializer.data, status=status.HTTP_200_OK)        


class ForgetPasswordAPI(generics.GenericAPIView):
    serializer_class=ForgetPasswordSerializer
    def post(self,request):
        serializer=self.serializer_class(data=request.data)
        email=request.data['email']
        if User.objects.filter(email=email).exists():
                user=User.objects.get(email=email)
                uidb64=urlsafe_base64_encode(smart_bytes(user.id))
                token=PasswordResetTokenGenerator().make_token(user)
                current_site=get_current_site(request=request).domain
                relativeLink=reverse('password-auth-token',kwargs={'uidb64':uidb64,'token':token})
                absurl='http://'+current_site+relativeLink
                email_body='Hello \n Use link below to reset your password \n'+absurl
                data={'email_body':email_body,'to_email':[user.email],'email_subject':'Reset your password',}
                Util.send_email(data)
        return Response({'success':'we have sent a link to reset your password'},status=status.HTTP_200_OK)


class PasswordTOkenCheckAPI(generics.GenericAPIView):
    serializer_class = RegisterSerializer
    def get(self,request,uidb64,token):
        try:
            id=smart_bytes(urlsafe_base64_decode(uidb64))
            user=User.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user,token):
                return Response({'error':'Token is ampared with, Please request a new one'},status=status.HTTP_401_UNAUTHORIZED)
            return Response({'success':True,'message':"Verified",'uidb64':uidb64,'token':token},status=status.HTTP_200_OK)
        except DjangoUnicodeDecodeError:return Response({'error':'Token is not valid'},status=status.HTTP_401_UNAUTHORIZED)




class ResetPassword(generics.GenericAPIView):
    serializer_class = ResetPasswordSerializer
    def patch(self,request):
        serializer=self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'success':True,'message':'Password reset success'},status=status.HTTP_201_CREATED)


class Logout(generics.GenericAPIView): 
    def get(self, request): 
        logout(request) 
        return Response(status=status.HTTP_200_OK)
