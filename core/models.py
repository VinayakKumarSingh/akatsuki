from django.db import models
from django.contrib.auth.models import AbstractUser
import uuid

class User(AbstractUser):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    # JSON field for attributes e.g., {"department": "Engineering", "role": "Developer"}
    attributes = models.JSONField(default=dict, blank=True)

class UserKeys(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='keys')
    salt = models.CharField(max_length=128) # For password-derived key
    rsa_public_key = models.TextField() # Plaintext PEM
    encrypted_rsa_private_key = models.TextField() # Encrypted with user's password
    encrypted_abe_secret_key = models.TextField(null=True, blank=True) # Encrypted with user's RSA public key
    otp_secret = models.CharField(max_length=32, blank=True, null=True)
    otp_enabled = models.BooleanField(default=False)

class Document(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='owned_documents')
    encrypted_filename = models.TextField() # File name encrypted with K_AES
    created_at = models.DateTimeField(auto_now_add=True)
    policy_string = models.CharField(max_length=255, blank=True) # Stored for UI reference

class DocumentVersion(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    document = models.ForeignKey(Document, on_delete=models.CASCADE, related_name='versions')
    version_number = models.PositiveIntegerField() # e.g. 1, 2, 3...
    file_path = models.FileField(upload_to='encrypted_docs/')
    iv = models.CharField(max_length=256) # Initialization vector for AES
    created_at = models.DateTimeField(auto_now_add=True)

class Group(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='created_groups')
    created_at = models.DateTimeField(auto_now_add=True)

class GroupMembership(models.Model):
    group = models.ForeignKey(Group, on_delete=models.CASCADE, related_name='memberships')
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='group_memberships')
    encrypted_group_key = models.TextField() # Group symmetric key wrapped with user's public RSA key
    role = models.CharField(max_length=20, choices=(('ADMIN', 'Admin'), ('MEMBER', 'Member')), default='MEMBER')
    created_at = models.DateTimeField(auto_now_add=True)

class DocumentAccessKey(models.Model):
    KEY_TYPES = (
        ('RSA', 'RSA Encrypted'),
        ('ABE', 'ABE Encrypted'),
        ('GRP', 'Group Encrypted'),
    )
    PERMISSION_CHOICES = (
        ('VIEW_ONLY', 'View Only'),
        ('DOWNLOAD', 'Download'),
        ('SHARE', 'Share'),
    )
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    version = models.ForeignKey(DocumentVersion, on_delete=models.CASCADE, related_name='access_keys', null=True, blank=True)
    recipient = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True, related_name='received_keys')
    group = models.ForeignKey(Group, on_delete=models.CASCADE, null=True, blank=True, related_name='received_keys')
    key_type = models.CharField(max_length=3, choices=KEY_TYPES)
    encrypted_key = models.TextField() # C_key_RSA, C_key_ABE, or wrapped with group symmetric key
    permissions = models.CharField(max_length=15, choices=PERMISSION_CHOICES, default='DOWNLOAD')

class DocumentAccessRequest(models.Model):
    STATUS_CHOICES = (
        ('PENDING', 'Pending'),
        ('APPROVED', 'Approved'),
        ('DENIED', 'Denied'),
    )
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    document = models.ForeignKey(Document, on_delete=models.CASCADE, related_name='access_requests')
    requester = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sent_requests')
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='PENDING')
    created_at = models.DateTimeField(auto_now_add=True)

class AuditLog(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='audit_logs')
    encrypted_log = models.TextField() # format: wrapped_aes_key:iv:ciphertext
    created_at = models.DateTimeField(auto_now_add=True)


