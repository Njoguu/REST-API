from rest_framework import serializers
from .models import User
from django.contrib import auth
from rest_framework.exceptions import AuthenticationFailed

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=68, min_length=6, write_only=True)

    class Meta:
        model = User
        fields = ['email', 'username', 'password']

    def validate(self, attrs):
        email = attrs.get('email', '')
        username = attrs.get('username', '')

        if not username.isalnum():
            raise serializers.ValidationError('Username should only have Alphanumeric Characters')
        
        return attrs
    
    def create(self, validated_data):
        return User.objects.create_user(**validated_data)
        

class EmailVerificationSerializer(serializers.ModelSerializer):
    token = serializers.CharField(max_length=555)

    class Meta:
        model = User
        fields = ['token']


class LoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255,min_length=3)
    password = serializers.CharField(max_length=50, min_length=6, write_only=True)
    username = serializers.CharField(max_length=255,min_length=3, read_only=True)
    tokens = serializers.CharField(max_length=50, min_length=6, read_only=True)

    class Meta:
        model = User
        fields = ['email', 'password', 'username', 'tokens']



    def validate(self, attrs):
        email = attrs.get('email', '')
        password = attrs.get('password', '')

        user = auth.authenticate(email=email, password=password)

        if not user:
            raise AuthenticationFailed('Invalid username or password. Please Try again!')

        if not user.is_active:
            raise AuthenticationFailed('Account Disabled, please contact the admin!')

        if not user.is_verified:
            raise AuthenticationFailed('Please verify your email to acces your account!')

        return {
            'email': user.email,
            'username': user.username,
            'tokens': user.tokens
        }
