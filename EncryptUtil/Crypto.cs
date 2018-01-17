using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace EncryptUtil
{
    public class EncryptUtil
    {
        private static StringBuilder sb;
        private static string Key { get; set; }

        /// <summary>
        /// Method that generates a random encryption key
        /// </summary>
        /// <param name="length">Key length. Min value: 6</param>
        public void GenerateKey(int length)
        {
            length = Math.Max(length, 6);
            byte[] buffer = new byte[length];
            RandomNumberGenerator.Create().GetBytes(buffer);

            Key = Convert.ToBase64String(buffer)
                .Replace("/", "").Replace("+", "").Replace("=", "")
                .Remove(length);
        }

        /// <summary>
        /// Method that encrypts entered string with AES encryption using previous generated key
        /// </summary>
        /// <param name="raw">String that will be encrypted</param>
        /// <returns>Encrypted string</returns>
        public static string Encrypt(string raw)
        {
            byte[] rawBytes = Encoding.Unicode.GetBytes(raw);

            //Defines cripto object used inside scope
            using (Aes encryptor = Aes.Create())
            {
                //Required for salt
                Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(Key, new byte[] { 0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76 });
                encryptor.Key = pdb.GetBytes(32);
                encryptor.IV = pdb.GetBytes(16);
                //Stream that will store encrypted bytes
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(rawBytes, 0, rawBytes.Length);
                        cs.Close();
                    }

                    //Converts to base64string stream byte array
                    sb = new StringBuilder(Convert.ToBase64String(ms.ToArray()));

                    //Removes the 2 last padding characters and removes the ones that could mess with URLs
                    return sb.Replace("+", "-").Replace("/", "_").Replace("=", ".").Remove(sb.Length - 2, 2).ToString();
                }
            }
        }

    }
}
