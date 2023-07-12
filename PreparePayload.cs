using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

public class PreparePayload
{
    public static void Main()
    {
        // PROGRAM TO GET BASE64, KEY AND IV
        // Path to the file to be encrypted
        string filePath = "C:\\Path\\To\\client.exe";

        byte[] fileBytes = File.ReadAllBytes(filePath);

        byte[] key, iv;
        byte[] encryptedBytes = EncryptBytes(fileBytes, out key, out iv);

        string hexKey = BitConverter.ToString(key).Replace("-", string.Empty);
        string hexIv = BitConverter.ToString(iv).Replace("-", string.Empty);

        string base64String = Convert.ToBase64String(encryptedBytes);

        // Print the hexadecimal key, IV, and base64 string
        Console.WriteLine($"Key: {hexKey}");
        Console.WriteLine($"IV: {hexIv}");
        Console.WriteLine($"Base64: {base64String}");
    }

    public static byte[] EncryptBytes(byte[] clearBytes, out byte[] key, out byte[] iv)
    {
        byte[] encrypted;
        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.GenerateKey();
            aesAlg.GenerateIV();

            key = aesAlg.Key;
            iv = aesAlg.IV;

            ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

            using (MemoryStream msEncrypt = new MemoryStream())
            {
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    csEncrypt.Write(clearBytes, 0, clearBytes.Length);
                    csEncrypt.FlushFinalBlock();
                    encrypted = msEncrypt.ToArray();
                }
            }
        }

        return encrypted;
    }
}
