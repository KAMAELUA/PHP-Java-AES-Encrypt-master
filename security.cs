using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace LauncherBeta
{
    class Security
    {
        public static String encrypt(String imput, String key)
        {
            String cipherText;
            var rijndael = new RijndaelManaged()
            {
                Key = Encoding.UTF8.GetBytes(key),
                Mode = CipherMode.ECB,
                BlockSize = 128,
                Padding = PaddingMode.PKCS7,
            };
            ICryptoTransform encryptor = rijndael.CreateEncryptor(rijndael.Key, null);
            using (var memoryStream = new MemoryStream())
            {
                using (var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                {
                    using (var streamWriter = new StreamWriter(cryptoStream))
                    {
                        streamWriter.Write(imput);
                        streamWriter.Flush();
                    }
                    cipherText = Convert.ToBase64String(memoryStream.ToArray());
                }
            }

            return cipherText;
        }

        public static String decrypt(String imput, String key)
        {
            byte[] data = Convert.FromBase64String(imput);
            String decrypted;
            
            using (RijndaelManaged rijAlg = new RijndaelManaged())
            {
                rijAlg.Key = Encoding.UTF8.GetBytes(key);
                rijAlg.Mode = CipherMode.ECB;
                rijAlg.BlockSize = 128;
                rijAlg.Padding = PaddingMode.PKCS7;

                ICryptoTransform decryptor = rijAlg.CreateDecryptor(rijAlg.Key, null);
                using (MemoryStream msDecrypt = new MemoryStream(data))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            decrypted = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }
            return decrypted;
        }
    }
}
