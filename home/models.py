from django.db import models
from django.contrib.auth.models import User

class LoginInfo(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    fails = models.PositiveSmallIntegerField(default=0)
    login_link = models.CharField(unique=True, blank=True, null=True, max_length=225)
    reset_link = models.CharField(unique=True, blank=True, null=True, max_length=225)
    pts = models.CharField(unique=False, blank=True, null= True, max_length= 500)
    passtype = models.PositiveSmallIntegerField(default=0)
    sec_key= models.CharField(unique=False, blank=True, null= True, max_length= 500)

    def __str__(self):
        return self.user.username
