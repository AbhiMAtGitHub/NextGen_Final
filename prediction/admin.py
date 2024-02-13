from django.contrib import admin
from .models import UserToken
# Register your models here.
 
admin.site.site_header = 'NextGen Retail Admin'
admin.site.site_title = 'NextGen Retail Admin Panel'
 
class UserTokenAdmin(admin.ModelAdmin):
    list_display = ('email', 'reset_password_token')
    search_fields = ('email',)
    list_filter = ('reset_password_token',)
 
admin.site.register(UserToken, UserTokenAdmin)
