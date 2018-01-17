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
        private static byte[] salt = new byte[] { 0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76 };

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
                //Required for salting
                Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(Key, salt);
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

                    //Converts stream byte array to base64string 
                    sb = new StringBuilder(Convert.ToBase64String(ms.ToArray()));

                    //Removes the 2 last padding characters and removes the ones that could mess with URLs
                    return sb.Replace("+", "-").Replace("/", "_").Replace("=", ".").Remove(sb.Length - 2, 2).ToString();
                }
            }
        }

        /// <summary>
        /// Method that decrypts entered string with previous generated key
        /// </summary>
        /// <param name="encrypted">Previously encrypted string</param>
        /// <returns>Decrypted string</returns>
        public static string Decrypt(string encrypted)
        {
            sb = new StringBuilder(encrypted);

            //Re-insert previous characters for proper decrypting
            encrypted = sb.Replace("-", "+").Replace("_", "/").Replace(".", "=").Replace(" ", "+")
                .Insert(encrypted.Length, "==").ToString();

            byte[] cipherBytes = Convert.FromBase64String(encrypted);

            //Defines cripto object used inside scope
            using (Aes encryptor = Aes.Create())
            {
                //Required for salting
                Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(Key, salt);
                encryptor.Key = pdb.GetBytes(32);
                encryptor.IV = pdb.GetBytes(16);
                //Stream that will store decrypted char sequence
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(cipherBytes, 0, cipherBytes.Length);
                        cs.Close();
                    }

                    //Finally, returns string previously encrypted using the same key
                    return Encoding.Unicode.GetString(ms.ToArray());
                }
            }
        }
    }
}
