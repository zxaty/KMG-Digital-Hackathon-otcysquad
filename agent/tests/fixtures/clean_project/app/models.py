from django.contrib.auth.models import AbstractUser
from django.db import models
from .fields import EncryptedCharField, EncryptedEmailField
class User(AbstractUser):
    username = EncryptedCharField(max_length=150, unique=True)
    first_name = EncryptedCharField(max_length=150, blank=True)
    last_name = EncryptedCharField(max_length=150, blank=True)
    email = EncryptedEmailField(blank=True)
    role = models.CharField(max_length=20, default='applicant')
class Ticket(models.Model):
    title = models.CharField(max_length=200)
    status = models.IntegerField(default=1)
    owner = models.ForeignKey(User, on_delete=models.PROTECT)
