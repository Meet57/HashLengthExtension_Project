# hash_extension/models.py
from django.contrib.auth.models import User
from django.db import models


class Image(models.Model):
    title = models.CharField(max_length=100)
    image = models.ImageField(upload_to="images/")
    owner = models.ForeignKey(User, on_delete=models.CASCADE)

    def __str__(self):
        return self.title


class CounterMeasure(models.Model):
    hmac = models.BooleanField(default=False)
    sha385 = models.BooleanField(default=False)

    @classmethod
    def create_sample(cls):
        # Create a sample instance
        sample_instance = cls.objects.create(hmac=False, sha385=False)
        return sample_instance
