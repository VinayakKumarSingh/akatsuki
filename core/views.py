from rest_framework import generics, status, views, viewsets
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes, action
from rest_framework.permissions import AllowAny, IsAuthenticated
from django.contrib.auth import get_user_model
from django.db.models import Q
from django.http import FileResponse
from .models import UserKeys, Document, DocumentAccessKey, DocumentAccessRequest, AuditLog, Group, GroupMembership
from .serializers import RegisterSerializer, UserKeysSerializer, DocumentSerializer, UserSerializer, DocumentAccessRequestSerializer, AuditLogSerializer, GroupSerializer
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.views import TokenObtainPairView
import json
import time
import hmac
import hashlib
import base64
import struct
import secrets

User = get_user_model()

class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    permission_classes = (AllowAny,)
    serializer_class = RegisterSerializer

class KeyMeView(generics.RetrieveUpdateAPIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = UserKeysSerializer

    def get_object(self):
        return self.request.user.keys

    def get(self, request, *args, **kwargs):
        keys = self.get_object()
        serializer = self.get_serializer(keys)
        data = serializer.data
        data['username'] = request.user.username
        data['user_id'] = request.user.id
        return Response(data)

    def put(self, request, *args, **kwargs):
        keys = self.get_object()
        salt = request.data.get('salt')
        rsa_public_key = request.data.get('rsa_public_key')
        encrypted_rsa_private_key = request.data.get('encrypted_rsa_private_key')

        if not salt or not encrypted_rsa_private_key:
            return Response({"error": "Salt and encrypted private key are required."}, status=status.HTTP_400_BAD_REQUEST)

        keys.salt = salt
        if rsa_public_key:
            keys.rsa_public_key = rsa_public_key
        keys.encrypted_rsa_private_key = encrypted_rsa_private_key
        keys.save()

        return Response({"success": "Keys updated successfully."})

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def change_password(request):
    user = request.user
    old_password = request.data.get('old_password')
    new_password = request.data.get('new_password')
    new_salt = request.data.get('new_salt')
    new_encrypted_rsa_private_key = request.data.get('new_encrypted_rsa_private_key')

    if not user.check_password(old_password):
        return Response({"error": "Incorrect old password"}, status=status.HTTP_400_BAD_REQUEST)
    
    user.set_password(new_password)
    user.save()
    
    user.keys.salt = new_salt
    user.keys.encrypted_rsa_private_key = new_encrypted_rsa_private_key
    user.keys.save()
    
    return Response({"success": "Password updated"})

class PublicKeyListView(views.APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        user_ids = request.query_params.get('user_ids', '')
        if not user_ids:
            # If no IDs, return all users
            users = User.objects.all()
        else:
            ids = [uid.strip() for uid in user_ids.split(',') if uid.strip()]
            users = User.objects.filter(id__in=ids)
        
        data = []
        for u in users:
            if hasattr(u, 'keys'):
                data.append({
                    'id': str(u.id),
                    'username': u.username,
                    'rsa_public_key': u.keys.rsa_public_key
                })
        return Response(data)

class ABEParametersView(views.APIView):
    permission_classes = (AllowAny,)
    
    def get(self, request):
        # Stub for ABE PK parameters.
        return Response({
            "PK": "STUB_ABE_PUBLIC_PARAMETERS"
        })

class GroupViewSet(viewsets.ModelViewSet):
    serializer_class = GroupSerializer
    permission_classes = (IsAuthenticated,)

    def get_queryset(self):
        user = self.request.user
        return Group.objects.filter(memberships__user=user).distinct()

    def perform_create(self, serializer):
        from rest_framework.exceptions import ValidationError
        creator_wrapped_key = self.request.data.get('creator_wrapped_key')
        if not creator_wrapped_key:
            raise ValidationError("Group symmetric key (creator_wrapped_key) is required.")
        
        group = serializer.save(created_by=self.request.user)
        GroupMembership.objects.create(
            group=group,
            user=self.request.user,
            encrypted_group_key=creator_wrapped_key,
            role='ADMIN'
        )

    @action(detail=True, methods=['post'])
    def add_member(self, request, pk=None):
        group = self.get_object()
        is_admin = group.memberships.filter(user=request.user, role='ADMIN').exists()
        if not is_admin:
            return Response({"error": "Only group administrators can add members."}, status=status.HTTP_403_FORBIDDEN)
        
        user_id = request.data.get('user_id')
        encrypted_group_key = request.data.get('encrypted_group_key')
        role = request.data.get('role', 'MEMBER')

        if not user_id or not encrypted_group_key:
            return Response({"error": "user_id and encrypted_group_key are required."}, status=status.HTTP_400_BAD_REQUEST)

        member = User.objects.filter(id=user_id).first()
        if not member:
            return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)

        GroupMembership.objects.update_or_create(
            group=group,
            user=member,
            defaults={'encrypted_group_key': encrypted_group_key, 'role': role}
        )
        return Response({"success": "Member added successfully."})

    @action(detail=True, methods=['post'])
    def remove_member(self, request, pk=None):
        group = self.get_object()
        is_admin = group.memberships.filter(user=request.user, role='ADMIN').exists()
        if not is_admin:
            return Response({"error": "Only group administrators can remove members."}, status=status.HTTP_403_FORBIDDEN)

        user_id = request.data.get('user_id')
        if not user_id:
            return Response({"error": "user_id is required."}, status=status.HTTP_400_BAD_REQUEST)

        member = User.objects.filter(id=user_id).first()
        if not member:
            return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)

        if member == request.user:
            admin_count = group.memberships.filter(role='ADMIN').count()
            if admin_count <= 1:
                return Response({"error": "Cannot remove the only administrator."}, status=status.HTTP_400_BAD_REQUEST)

        group.memberships.filter(user=member).delete()
        return Response({"success": "Member removed successfully."})

class DocumentViewSet(viewsets.ModelViewSet):
    serializer_class = DocumentSerializer
    permission_classes = (IsAuthenticated,)

    def get_queryset(self):
        user = self.request.user
        # Documents where the user is the owner, or is a direct recipient (RSA) of any version, or there is an ABE key, OR belongs to a group with access
        return Document.objects.filter(
            Q(owner=user) | 
            Q(versions__access_keys__recipient=user) | 
            Q(versions__access_keys__key_type='ABE') |
            Q(versions__access_keys__group__memberships__user=user)
        ).distinct()

    def create(self, request, *args, **kwargs):
        document_id = request.data.get('document_id')
        if document_id:
            doc = Document.objects.filter(id=document_id).first()
            if not doc:
                return Response({"error": "Document not found."}, status=status.HTTP_404_NOT_FOUND)
            if doc.owner != request.user:
                return Response({"error": "Unauthorized to upload version to this document."}, status=status.HTTP_403_FORBIDDEN)
            
            # Create new version
            latest_version = doc.versions.order_by('-version_number').first()
            version_num = (latest_version.version_number + 1) if latest_version else 1
            
            from .models import DocumentVersion
            version = DocumentVersion.objects.create(
                document=doc,
                version_number=version_num,
                file_path=request.FILES['file'],
                iv=request.data.get('iv')
            )
            
            keys_data = request.data.get('keys')
            if keys_data:
                try:
                    keys = json.loads(keys_data)
                    for key_info in keys:
                        recipient_id = key_info.get('recipient_id')
                        group_id = key_info.get('group_id')
                        recipient = User.objects.filter(id=recipient_id).first() if recipient_id else None
                        group = Group.objects.filter(id=group_id).first() if group_id else None
                        DocumentAccessKey.objects.create(
                            version=version,
                            recipient=recipient,
                            group=group,
                            key_type=key_info.get('key_type', 'RSA' if recipient else 'GRP'),
                            encrypted_key=key_info.get('encrypted_key'),
                            permissions=key_info.get('permissions', 'DOWNLOAD')
                        )
                except json.JSONDecodeError:
                    pass
            
            serializer = self.get_serializer(doc)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
            
        else:
            return super().create(request, *args, **kwargs)

    def perform_create(self, serializer):
        doc = serializer.save(owner=self.request.user)
        
        # Create version 1
        from .models import DocumentVersion
        version = DocumentVersion.objects.create(
            document=doc,
            version_number=1,
            file_path=self.request.FILES['file'],
            iv=self.request.data.get('iv')
        )
        
        keys_data = self.request.data.get('keys')
        if keys_data:
            try:
                keys = json.loads(keys_data)
                for key_info in keys:
                    recipient_id = key_info.get('recipient_id')
                    group_id = key_info.get('group_id')
                    recipient = User.objects.filter(id=recipient_id).first() if recipient_id else None
                    group = Group.objects.filter(id=group_id).first() if group_id else None
                    DocumentAccessKey.objects.create(
                        version=version,
                        recipient=recipient,
                        group=group,
                        key_type=key_info.get('key_type', 'RSA' if recipient else 'GRP'),
                        encrypted_key=key_info.get('encrypted_key'),
                        permissions=key_info.get('permissions', 'DOWNLOAD')
                    )
            except json.JSONDecodeError:
                pass

    @action(detail=True, methods=['get'])
    def download(self, request, pk=None):
        doc = self.get_object()
        user = request.user

        # Determine version
        version_id = request.query_params.get('version_id')
        if version_id:
            version = doc.versions.filter(id=version_id).first()
        else:
            version = doc.versions.order_by('-version_number').first()

        if not version:
            return Response({"error": "Version not found."}, status=status.HTTP_404_NOT_FOUND)

        # Owner has full permission
        if doc.owner == user:
            return FileResponse(version.file_path.open('rb'))

        # Check recipient permissions on this version
        access_key = version.access_keys.filter(recipient=user).first()
        if access_key and access_key.permissions in ['DOWNLOAD', 'SHARE']:
            return FileResponse(version.file_path.open('rb'))

        # Check group permissions on this version
        group_keys = version.access_keys.filter(group__memberships__user=user)
        for gkey in group_keys:
            if gkey.permissions in ['DOWNLOAD', 'SHARE']:
                return FileResponse(version.file_path.open('rb'))

        return Response({"error": "Download permission denied."}, status=status.HTTP_403_FORBIDDEN)

    @action(detail=True, methods=['post'])
    def rekey(self, request, pk=None):
        doc = self.get_object()
        if doc.owner != request.user:
            return Response({"error": "Only the document owner can revoke access and re-encrypt files."}, status=status.HTTP_403_FORBIDDEN)
        
        # 1. Create new version
        latest_version = doc.versions.order_by('-version_number').first()
        version_num = (latest_version.version_number + 1) if latest_version else 1
        
        from .models import DocumentVersion
        version = DocumentVersion.objects.create(
            document=doc,
            version_number=version_num,
            file_path=request.FILES['file'],
            iv=request.data.get('iv')
        )
        
        # 2. Add new access keys for this version
        keys_data = request.data.get('keys')
        if keys_data:
            try:
                keys = json.loads(keys_data)
                for key_info in keys:
                    recipient_id = key_info.get('recipient_id')
                    group_id = key_info.get('group_id')
                    recipient = User.objects.filter(id=recipient_id).first() if recipient_id else None
                    group = Group.objects.filter(id=group_id).first() if group_id else None
                    DocumentAccessKey.objects.create(
                        version=version,
                        recipient=recipient,
                        group=group,
                        key_type=key_info.get('key_type', 'RSA' if recipient else 'GRP'),
                        encrypted_key=key_info.get('encrypted_key'),
                        permissions=key_info.get('permissions', 'DOWNLOAD')
                    )
            except json.JSONDecodeError:
                pass

        # 3. Clean up: Delete access keys matching the revoked recipient/group from ALL versions of this document
        revoked_user_id = request.data.get('revoked_user_id')
        revoked_group_id = request.data.get('revoked_group_id')
        
        if revoked_user_id:
            DocumentAccessKey.objects.filter(version__document=doc, recipient_id=revoked_user_id).delete()
        if revoked_group_id:
            DocumentAccessKey.objects.filter(version__document=doc, group_id=revoked_group_id).delete()

        serializer = self.get_serializer(doc)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(detail=True, methods=['post'])
    def grant_access(self, request, pk=None):
        doc = self.get_object()
        if doc.owner != request.user:
            return Response({"error": "Only the document owner can grant access."}, status=status.HTTP_403_FORBIDDEN)

        recipient_id = request.data.get('recipient_id')
        group_id = request.data.get('group_id')
        encrypted_key = request.data.get('encrypted_key')
        permissions = request.data.get('permissions', 'DOWNLOAD')

        if not encrypted_key:
            return Response({"error": "encrypted_key is required."}, status=status.HTTP_400_BAD_REQUEST)

        latest_version = doc.versions.order_by('-version_number').first()
        if not latest_version:
            return Response({"error": "No version exists for this document."}, status=status.HTTP_400_BAD_REQUEST)

        recipient = User.objects.filter(id=recipient_id).first() if recipient_id else None
        group = Group.objects.filter(id=group_id).first() if group_id else None

        if not recipient and not group:
            return Response({"error": "Either recipient_id or group_id is required."}, status=status.HTTP_400_BAD_REQUEST)

        if recipient:
            DocumentAccessKey.objects.update_or_create(
                version=latest_version,
                recipient=recipient,
                defaults={'encrypted_key': encrypted_key, 'permissions': permissions, 'key_type': 'RSA'}
            )
        else:
            DocumentAccessKey.objects.update_or_create(
                version=latest_version,
                group=group,
                defaults={'encrypted_key': encrypted_key, 'permissions': permissions, 'key_type': 'GRP'}
            )

        serializer = self.get_serializer(doc)
        return Response(serializer.data, status=status.HTTP_200_OK)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def request_access(request, doc_id):
    doc = Document.objects.filter(id=doc_id).first()
    if not doc:
        return Response({"error": "Document not found."}, status=status.HTTP_404_NOT_FOUND)

    # Check if user already has full download/share access to any version of the document
    has_full_access = DocumentAccessKey.objects.filter(
        version__document=doc,
        recipient=request.user,
        permissions__in=['DOWNLOAD', 'SHARE']
    ).exists()

    if doc.owner == request.user or has_full_access:
        return Response({"error": "You already have access to this document."}, status=status.HTTP_400_BAD_REQUEST)

    # Check if there is already a pending request
    if DocumentAccessRequest.objects.filter(document=doc, requester=request.user, status='PENDING').exists():
        return Response({"error": "You already have a pending request for this document."}, status=status.HTTP_400_BAD_REQUEST)

    req, created = DocumentAccessRequest.objects.get_or_create(
        document=doc,
        requester=request.user,
        status='PENDING'
    )
    return Response({"success": "Access requested successfully."})

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def list_pending_requests(request):
    reqs = DocumentAccessRequest.objects.filter(document__owner=request.user, status='PENDING')
    serializer = DocumentAccessRequestSerializer(reqs, many=True)
    return Response(serializer.data)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def approve_request(request, req_id):
    req = DocumentAccessRequest.objects.filter(id=req_id, document__owner=request.user).first()
    if not req:
        return Response({"error": "Request not found or unauthorized."}, status=status.HTTP_404_NOT_FOUND)

    encrypted_key = request.data.get('encrypted_key')
    permissions = request.data.get('permissions', 'DOWNLOAD')

    if not encrypted_key:
        return Response({"error": "Encrypted AES key is required for approval."}, status=status.HTTP_400_BAD_REQUEST)

    # We approve access to the latest version of the document
    latest_version = req.document.versions.order_by('-version_number').first()
    if not latest_version:
        return Response({"error": "No version exists for this document to approve access to."}, status=status.HTTP_400_BAD_REQUEST)

    # Update existing key if it exists, otherwise create a new one
    access_key = DocumentAccessKey.objects.filter(version=latest_version, recipient=req.requester).first()
    if access_key:
        access_key.encrypted_key = encrypted_key
        access_key.permissions = permissions
        access_key.save()
    else:
        DocumentAccessKey.objects.create(
            version=latest_version,
            recipient=req.requester,
            key_type='RSA',
            encrypted_key=encrypted_key,
            permissions=permissions
        )

    req.status = 'APPROVED'
    req.save()
    return Response({"success": "Request approved."})

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def deny_request(request, req_id):
    req = DocumentAccessRequest.objects.filter(id=req_id, document__owner=request.user).first()
    if not req:
        return Response({"error": "Request not found or unauthorized."}, status=status.HTTP_404_NOT_FOUND)

    req.status = 'DENIED'
    req.save()
    return Response({"success": "Request denied."})

# --- 2FA & Audit Log Implementation ---

def verify_totp(secret, code):
    try:
        key = base64.b32decode(secret, casefold=True)
    except Exception:
        return False
    
    now = int(time.time()) // 30
    for t in [now - 1, now, now + 1]:
        msg = struct.pack(">Q", t)
        hmac_hash = hmac.new(key, msg, hashlib.sha1).digest()
        offset = hmac_hash[-1] & 0xf
        code_val = (struct.unpack(">I", hmac_hash[offset:offset+4])[0] & 0x7fffffff) % 1000000
        if f"{code_val:06d}" == str(code).strip():
            return True
    return False

class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        username = attrs.get(self.username_field)
        from django.contrib.auth import authenticate
        user = authenticate(username=username, password=attrs.get('password'))
        
        if user is not None:
            if hasattr(user, 'keys') and user.keys.otp_enabled:
                otp_code = self.context['request'].data.get('otp_code')
                if not otp_code:
                    from rest_framework.exceptions import ValidationError
                    raise ValidationError({
                        "requires_2fa": True,
                        "message": "Two-factor authentication code is required."
                    })
                
                if not verify_totp(user.keys.otp_secret, otp_code):
                    from rest_framework.exceptions import ValidationError
                    raise ValidationError({
                        "error": "Invalid two-factor authentication code."
                    })
        
        return super().validate(attrs)

class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def setup_2fa(request):
    keys = request.user.keys
    if keys.otp_enabled:
        return Response({"error": "2FA is already enabled."}, status=status.HTTP_400_BAD_REQUEST)
    
    random_bytes = secrets.token_bytes(10)
    secret = base64.b32encode(random_bytes).decode('utf-8')
    keys.otp_secret = secret
    keys.save()

    otpauth_url = f"otpauth://totp/Akatsuki:{request.user.username}?secret={secret}&issuer=Akatsuki"

    return Response({
        "secret": secret,
        "otpauth_url": otpauth_url
    })

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def verify_2fa(request):
    keys = request.user.keys
    code = request.data.get('code')
    if not code:
        return Response({"error": "OTP code is required."}, status=status.HTTP_400_BAD_REQUEST)
    
    if not keys.otp_secret:
        return Response({"error": "2FA setup has not been initiated."}, status=status.HTTP_400_BAD_REQUEST)
    
    if verify_totp(keys.otp_secret, code):
        keys.otp_enabled = True
        keys.save()
        return Response({"success": "2FA enabled successfully."})
    else:
        return Response({"error": "Invalid OTP code."}, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def disable_2fa(request):
    keys = request.user.keys
    code = request.data.get('code')
    if not code:
        return Response({"error": "OTP code is required."}, status=status.HTTP_400_BAD_REQUEST)
    
    if not keys.otp_enabled:
        return Response({"error": "2FA is not enabled."}, status=status.HTTP_400_BAD_REQUEST)
    
    if verify_totp(keys.otp_secret, code):
        keys.otp_enabled = False
        keys.otp_secret = None
        keys.save()
        return Response({"success": "2FA disabled successfully."})
    else:
        return Response({"error": "Invalid OTP code."}, status=status.HTTP_400_BAD_REQUEST)

class AuditLogViewSet(viewsets.ModelViewSet):
    serializer_class = AuditLogSerializer
    permission_classes = (IsAuthenticated,)

    def get_queryset(self):
        return self.request.user.audit_logs.all().order_by('-created_at')

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

from django.contrib.auth.hashers import check_password

@api_view(['POST'])
@permission_classes([AllowAny])
def get_security_question(request):
    username = request.data.get('username')
    if not username:
        return Response({"error": "Username is required"}, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        user = User.objects.get(username=username)
        keys = user.keys
        if not keys.security_question:
            return Response({"error": "Security question not set for this user"}, status=status.HTTP_400_BAD_REQUEST)
        return Response({"security_question": keys.security_question})
    except (User.DoesNotExist, UserKeys.DoesNotExist):
        return Response({"error": "User or security question not found"}, status=status.HTTP_404_NOT_FOUND)

@api_view(['POST'])
@permission_classes([AllowAny])
def verify_security_answer(request):
    username = request.data.get('username')
    security_answer = request.data.get('security_answer')
    if not username or not security_answer:
        return Response({"error": "Username and security answer are required"}, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        user = User.objects.get(username=username)
        keys = user.keys
        
        normalized_answer = "".join(security_answer.lower().split())
        if not keys.security_answer_hash or not check_password(normalized_answer, keys.security_answer_hash):
            return Response({"error": "Incorrect security answer"}, status=status.HTTP_400_BAD_REQUEST)
            
        return Response({
            "recovery_salt": keys.recovery_salt,
            "encrypted_rsa_private_key_recovery": keys.encrypted_rsa_private_key_recovery
        })
    except (User.DoesNotExist, UserKeys.DoesNotExist):
        return Response({"error": "User or security question not found"}, status=status.HTTP_404_NOT_FOUND)

@api_view(['POST'])
@permission_classes([AllowAny])
def reset_password_with_recovery(request):
    username = request.data.get('username')
    security_answer = request.data.get('security_answer')
    new_password = request.data.get('new_password')
    new_salt = request.data.get('new_salt')
    new_encrypted_rsa_private_key = request.data.get('new_encrypted_rsa_private_key')
    
    if not all([username, security_answer, new_password, new_salt, new_encrypted_rsa_private_key]):
        return Response({"error": "All fields are required"}, status=status.HTTP_400_BAD_REQUEST)
        
    try:
        user = User.objects.get(username=username)
        keys = user.keys
        
        normalized_answer = "".join(security_answer.lower().split())
        if not keys.security_answer_hash or not check_password(normalized_answer, keys.security_answer_hash):
            return Response({"error": "Incorrect security answer"}, status=status.HTTP_400_BAD_REQUEST)
            
        user.set_password(new_password)
        user.save()
        
        keys.salt = new_salt
        keys.encrypted_rsa_private_key = new_encrypted_rsa_private_key
        keys.save()
        
        return Response({"success": "Password reset successfully"})
    except (User.DoesNotExist, UserKeys.DoesNotExist):
        return Response({"error": "User or security question not found"}, status=status.HTTP_404_NOT_FOUND)
