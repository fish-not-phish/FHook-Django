from django.contrib import admin
from .models import *

@admin.register(Hook)
class HookAdmin(admin.ModelAdmin):
    list_display = ['data']
    readonly_fields = ['uuid']

@admin.register(Client)
class ClientAdmin(admin.ModelAdmin):
    list_display = [ 'hook', 'data']

@admin.register(IP)
class IPAdmin(admin.ModelAdmin):
    list_display = ['hook', 'data']

@admin.register(Server)
class ServerAdmin(admin.ModelAdmin):
    list_display = ['running']

@admin.register(Command)
class CommandAdmin(admin.ModelAdmin):
    list_display = ['hook', 'command']

@admin.register(FileUpload)
class FileUploadAdmin(admin.ModelAdmin):
    list_display = ['user', 'file', 'filename', 'filetype', 'filesize']

@admin.register(Download)
class DownloadAdmin(admin.ModelAdmin):
    list_display = ['file', 'file_name']
