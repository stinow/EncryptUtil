using System;
using System.Security.Cryptography;

namespace EncryptUtil
{
    public class EncryptUtil
    {
        private static string EncryptionKey;

        /// <summary>
        /// Method that generates a random encryption key
        /// </summary>
        /// <param name="length">Key length. Min value: 6</param>
        public void GenerateKey(int length)
        {
            length = Math.Max(length, 6);
            byte[] buffer = new byte[length];
            RandomNumberGenerator.Create().GetBytes(buffer);

            EncryptionKey = Convert.ToBase64String(buffer)
                .Replace("/", "").Replace("+", "").Replace("=", "")
                .Remove(length);
        }

    }
}
