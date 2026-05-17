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

class Document(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='owned_documents')
    file_path = models.FileField(upload_to='encrypted_docs/') # Points to C_file
    encrypted_filename = models.TextField() # File name encrypted with K_AES
    iv = models.CharField(max_length=256) # Initialization vector for AES
    created_at = models.DateTimeField(auto_now_add=True)
    policy_string = models.CharField(max_length=255, blank=True) # Stored for UI reference

class DocumentAccessKey(models.Model):
    KEY_TYPES = (
        ('RSA', 'RSA Encrypted'),
        ('ABE', 'ABE Encrypted'),
    )
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    document = models.ForeignKey(Document, on_delete=models.CASCADE, related_name='access_keys')
    recipient = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True, related_name='received_keys')
    key_type = models.CharField(max_length=3, choices=KEY_TYPES)
    encrypted_key = models.TextField() # C_key_RSA or C_key_ABE
