from django.db import models
 
# Create your models here.
class UserToken(models.Model):
    email = models.EmailField(unique=True, default="default_mail")
    reset_password_token = models.CharField(max_length=100,blank=True,null=True)
   
    def __str__(self):
        return self.email  # Or any other representation you prefer
