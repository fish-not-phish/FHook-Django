from django.db import models
import uuid
from django.conf import settings
import os
from django.contrib.auth.models import User

def get_download_path(instance, filename):
    download_directory = os.path.join(settings.MEDIA_ROOT, 'downloads', str(instance.hook.uuid))
    os.makedirs(download_directory, exist_ok=True)
    unique_filename = os.path.join(download_directory, str(uuid.uuid4()) + '_' + filename)
    return unique_filename

class Hook(models.Model):
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True, null=True)
    data = models.CharField('Data', max_length=500, null=True, blank=True)

class Client(models.Model):
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True, null=True)
    hook = models.OneToOneField(Hook, on_delete=models.CASCADE, null=True)
    data = models.CharField('Data', max_length=500, null=True, blank=True)

class IP(models.Model):
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True, null=True)
    hook = models.OneToOneField(Hook, on_delete=models.CASCADE, null=True)
    data = models.CharField('Data', max_length=500, null=True, blank=True)
    port = models.CharField('Port', max_length=10, null=True, blank=True)

class Server(models.Model):
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True, null=True)
    running = models.BooleanField(default=True)
    restart = models.BooleanField(default=False)

class Command(models.Model):
    command = models.CharField('Command', max_length=500, null=True, blank=True)
    hook = models.ForeignKey(Hook, on_delete=models.CASCADE, null=True)
    response = models.TextField(blank=True, null=True)
    processed = models.BooleanField(default=False)
    file_response = models.FileField(upload_to=get_download_path, null=True, blank=True)

class Download(models.Model):
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True, null=True)
    command = models.ForeignKey(Command, on_delete=models.CASCADE, null=True)
    hook = models.ForeignKey(Hook, on_delete=models.CASCADE, null=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    file = models.FileField(upload_to=get_download_path, null=True)
    file_name = models.CharField('File Name', max_length=200, null=True, blank=True)

class Restart(models.Model):
    server = models.ForeignKey(Server, on_delete=models.CASCADE, null=True, related_name='restarts')
    execute = models.BooleanField(default=False)

class FileUpload(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    file = models.FileField(upload_to='user_files/')
    filename = models.CharField(max_length=255, blank=True)
    filesize = models.IntegerField(blank=True, null=True)  # in bytes
    filetype = models.CharField(max_length=255, blank=True)

    def save(self, *args, **kwargs):
        self.filename = self.file.name
        self.filesize = self.file.size
        super().save(*args, **kwargs)