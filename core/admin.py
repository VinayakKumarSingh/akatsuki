from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import User, UserKeys, Document, DocumentVersion, DocumentAccessKey, DocumentAccessRequest, AuditLog, Group, GroupMembership

@admin.register(User)
class CustomUserAdmin(UserAdmin):
    fieldsets = UserAdmin.fieldsets + (
        ('Custom Attributes', {'fields': ('attributes',)}),
    )
    list_display = ('username', 'email', 'first_name', 'last_name', 'is_staff')

@admin.register(UserKeys)
class UserKeysAdmin(admin.ModelAdmin):
    list_display = ('user', 'salt', 'otp_enabled')
    search_fields = ('user__username',)

@admin.register(Document)
class DocumentAdmin(admin.ModelAdmin):
    list_display = ('id', 'owner', 'created_at')
    search_fields = ('owner__username', 'id')

@admin.register(DocumentVersion)
class DocumentVersionAdmin(admin.ModelAdmin):
    list_display = ('id', 'document', 'version_number', 'created_at')
    search_fields = ('document__id', 'id')

@admin.register(DocumentAccessKey)
class DocumentAccessKeyAdmin(admin.ModelAdmin):
    list_display = ('id', 'version', 'recipient', 'group', 'key_type', 'permissions')
    search_fields = ('recipient__username', 'group__name', 'version__document__id')

@admin.register(DocumentAccessRequest)
class DocumentAccessRequestAdmin(admin.ModelAdmin):
    list_display = ('id', 'document', 'requester', 'status', 'created_at')
    search_fields = ('requester__username', 'document__id')

@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'created_at')
    search_fields = ('user__username', 'id')

@admin.register(Group)
class GroupAdmin(admin.ModelAdmin):
    list_display = ('id', 'name', 'created_by', 'created_at')
    search_fields = ('name', 'created_by__username')

@admin.register(GroupMembership)
class GroupMembershipAdmin(admin.ModelAdmin):
    list_display = ('id', 'group', 'user', 'role', 'created_at')
    search_fields = ('group__name', 'user__username')
