from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import UserKeys, Document, DocumentAccessKey

User = get_user_model()

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'attributes']

from django.contrib.auth.hashers import make_password

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    salt = serializers.CharField(write_only=True)
    rsa_public_key = serializers.CharField(write_only=True)
    encrypted_rsa_private_key = serializers.CharField(write_only=True)
    security_question = serializers.CharField(write_only=True)
    security_answer = serializers.CharField(write_only=True)
    recovery_salt = serializers.CharField(write_only=True)
    encrypted_rsa_private_key_recovery = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = [
            'username', 'password', 'salt', 'rsa_public_key', 'encrypted_rsa_private_key',
            'security_question', 'security_answer', 'recovery_salt', 'encrypted_rsa_private_key_recovery'
        ]

    def create(self, validated_data):
        salt = validated_data.pop('salt')
        rsa_pub = validated_data.pop('rsa_public_key')
        rsa_priv = validated_data.pop('encrypted_rsa_private_key')
        security_q = validated_data.pop('security_question')
        security_ans = validated_data.pop('security_answer')
        recovery_s = validated_data.pop('recovery_salt')
        rsa_priv_rec = validated_data.pop('encrypted_rsa_private_key_recovery')
        
        # Normalize security answer: lowercase and remove all whitespace
        normalized_answer = "".join(security_ans.lower().split())
        security_answer_hash = make_password(normalized_answer)
        
        user = User.objects.create_user(
            username=validated_data['username'],
            password=validated_data['password']
        )
        
        UserKeys.objects.create(
            user=user,
            salt=salt,
            rsa_public_key=rsa_pub,
            encrypted_rsa_private_key=rsa_priv,
            security_question=security_q,
            security_answer_hash=security_answer_hash,
            recovery_salt=recovery_s,
            encrypted_rsa_private_key_recovery=rsa_priv_rec
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
