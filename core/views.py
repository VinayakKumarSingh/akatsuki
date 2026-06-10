from rest_framework import generics, status, views, viewsets
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from django.contrib.auth import get_user_model
from django.db.models import Q
from .models import UserKeys, Document, DocumentAccessKey
from .serializers import RegisterSerializer, UserKeysSerializer, DocumentSerializer, UserSerializer
import json

User = get_user_model()

class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    permission_classes = (AllowAny,)
    serializer_class = RegisterSerializer

class KeyMeView(generics.RetrieveAPIView):
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
            # If no IDs, maybe return all users (for demo purposes)
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
        # Stub for ABE PK parameters. In a real scenario, this would return the generated PK from the KGC.
        return Response({
            "PK": "STUB_ABE_PUBLIC_PARAMETERS"
        })

class DocumentViewSet(viewsets.ModelViewSet):
    serializer_class = DocumentSerializer
    permission_classes = (IsAuthenticated,)

    def get_queryset(self):
        user = self.request.user
        # Documents where the user is the owner, or is a direct recipient (RSA), or there is an ABE key
        return Document.objects.filter(
            Q(owner=user) | 
            Q(access_keys__recipient=user) | 
            Q(access_keys__key_type='ABE')
        ).distinct()

    def perform_create(self, serializer):
        doc = serializer.save(owner=self.request.user)
        # Expecting a JSON string of keys in 'keys' form data field
        keys_data = self.request.data.get('keys')
        if keys_data:
            try:
                keys = json.loads(keys_data)
                for key_info in keys:
                    recipient_id = key_info.get('recipient_id')
                    recipient = User.objects.filter(id=recipient_id).first() if recipient_id else None
                    DocumentAccessKey.objects.create(
                        document=doc,
                        recipient=recipient,
                        key_type=key_info.get('key_type', 'RSA'),
                        encrypted_key=key_info.get('encrypted_key')
                    )
            except json.JSONDecodeError:
                pass

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
