using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Crypto
{
    public class MyCrypto
    {
        // Метод для шифрования сообщения.
        public string Crypt(string text, string key) 
        {
            string crypt = Encrypt(text, key);
            return crypt;
        }

        // Метод для дешифровки сообщения.
        public string DeCrypt(string text, string key)  
        {
            string decrypt = Decrypt(text, key);
            return decrypt;
        }

        // Шифровщик.
        private static string Encrypt(string clearText, string ekey)
        {
            string EncryptionKey = ekey;
            byte[] clearBytes = Encoding.Unicode.GetBytes(clearText);
            using(Aes encryptor = Aes.Create())
            {
                Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(EncryptionKey, new byte[] { 0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x75 }); // Формирование ключа на основе пароля.
                encryptor.Key = pdb.GetBytes(32);
                encryptor.IV = pdb.GetBytes(16);
                using(MemoryStream ms = new MemoryStream())
                {
                    using(CryptoStream cs = new CryptoStream(ms, encryptor.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(clearBytes, 0, clearBytes.Length);
                        cs.Close();
                    }
                    clearText = Convert.ToBase64String(ms.ToArray());
                }
            }
            return clearText;
        }

        // Дешифровщик.
        private static string Decrypt(string cipherText, string dkey)
        {
            string EncryptionKey = dkey;
            cipherText = cipherText.Replace(" ", "+");
            byte[] cipherBytes = Convert.FromBase64String(cipherText);
            using(Aes encryptor = Aes.Create())
            {
                Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(EncryptionKey, new byte[] { 0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x75 });
                encryptor.Key = pdb.GetBytes(32);
                encryptor.IV = pdb.GetBytes(16);
                using(MemoryStream ms = new MemoryStream())
                {
                    using(CryptoStream cs = new CryptoStream(ms, encryptor.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(cipherBytes, 0, cipherBytes.Length);
                        cs.Close();
                    }
                    cipherText = Encoding.Unicode.GetString(ms.ToArray());
                }
            }
            return cipherText;
        }

        // Генератор ключа.
        public string GetPass()
        {
            int[] arr = new int[6]; // Устанавливаем длину пароля в 6 символов.
            Random rnd = new Random();
            string Password = "";

            for(int i = 0; i < arr.Length; i++)
            {
                arr[i] = rnd.Next(33, 125);
                Password += (char)arr[i];
            }
            return Password;
        }
    }
}