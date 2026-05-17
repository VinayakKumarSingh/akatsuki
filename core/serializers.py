from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import UserKeys, Document, DocumentAccessKey

User = get_user_model()

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'attributes']

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    salt = serializers.CharField(write_only=True)
    rsa_public_key = serializers.CharField(write_only=True)
    encrypted_rsa_private_key = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['username', 'password', 'salt', 'rsa_public_key', 'encrypted_rsa_private_key']

    def create(self, validated_data):
        salt = validated_data.pop('salt')
        rsa_pub = validated_data.pop('rsa_public_key')
        rsa_priv = validated_data.pop('encrypted_rsa_private_key')
        
        user = User.objects.create_user(
            username=validated_data['username'],
            password=validated_data['password']
        )
        
        UserKeys.objects.create(
            user=user,
            salt=salt,
            rsa_public_key=rsa_pub,
            encrypted_rsa_private_key=rsa_priv
        )
        return user

class UserKeysSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserKeys
        fields = ['salt', 'rsa_public_key', 'encrypted_rsa_private_key', 'encrypted_abe_secret_key']

class DocumentAccessKeySerializer(serializers.ModelSerializer):
    class Meta:
        model = DocumentAccessKey
        fields = ['id', 'recipient', 'key_type', 'encrypted_key']

class DocumentSerializer(serializers.ModelSerializer):
    access_keys = DocumentAccessKeySerializer(many=True, read_only=True)
    
    class Meta:
        model = Document
        fields = ['id', 'owner', 'file_path', 'encrypted_filename', 'iv', 'created_at', 'policy_string', 'access_keys']
        read_only_fields = ['owner']
