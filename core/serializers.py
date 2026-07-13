from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import UserKeys, Document, DocumentVersion, DocumentAccessKey, DocumentAccessRequest, AuditLog, Group, GroupMembership

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
        fields = ['salt', 'rsa_public_key', 'encrypted_rsa_private_key', 'encrypted_abe_secret_key', 'otp_enabled']

class DocumentAccessKeySerializer(serializers.ModelSerializer):
    class Meta:
        model = DocumentAccessKey
        fields = ['id', 'recipient', 'group', 'key_type', 'encrypted_key', 'permissions']

class DocumentVersionSerializer(serializers.ModelSerializer):
    access_keys = DocumentAccessKeySerializer(many=True, read_only=True)
    
    class Meta:
        model = DocumentVersion
        fields = ['id', 'version_number', 'file_path', 'iv', 'created_at', 'access_keys']

class DocumentSerializer(serializers.ModelSerializer):
    versions = DocumentVersionSerializer(many=True, read_only=True)
    
    class Meta:
        model = Document
        fields = ['id', 'owner', 'encrypted_filename', 'created_at', 'policy_string', 'versions']
        read_only_fields = ['owner']

class DocumentAccessRequestSerializer(serializers.ModelSerializer):
    requester_username = serializers.CharField(source='requester.username', read_only=True)
    document_owner = serializers.CharField(source='document.owner.username', read_only=True)
    
    class Meta:
        model = DocumentAccessRequest
        fields = ['id', 'document', 'requester', 'requester_username', 'document_owner', 'status', 'created_at']
        read_only_fields = ['requester', 'status']

class AuditLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = AuditLog
        fields = ['id', 'user', 'encrypted_log', 'created_at']
        read_only_fields = ['user']

class GroupMembershipSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source='user.username', read_only=True)
    
    class Meta:
        model = GroupMembership
        fields = ['id', 'user', 'username', 'encrypted_group_key', 'role', 'created_at']
        read_only_fields = ['role', 'created_at']

class GroupSerializer(serializers.ModelSerializer):
    memberships = GroupMembershipSerializer(many=True, read_only=True)
    created_by_username = serializers.CharField(source='created_by.username', read_only=True)
    
    class Meta:
        model = Group
        fields = ['id', 'name', 'created_by', 'created_by_username', 'created_at', 'memberships']
        read_only_fields = ['created_by', 'created_at']

