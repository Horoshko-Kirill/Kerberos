using System.Security.Cryptography;
using System.Text;

namespace Kerberos
{
    public class CryptoHelper
    {
        public static byte[] Encrypt(string plainText, byte[] key)
        {
            using var aes = Aes.Create();
            aes.Key = key;
            aes.GenerateIV();

            using var encryptor = aes.CreateEncryptor();
            var plainBytes = Encoding.UTF8.GetBytes(plainText);
            var cipher = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);

            return aes.IV.Concat(cipher).ToArray(); 
        }

        public static string Decrypt(byte[] cipherData, byte[] key)
        {
            using var aes = Aes.Create();
            aes.Key = key;

            var iv = cipherData.Take(16).ToArray();
            var cipher = cipherData.Skip(16).ToArray();
            aes.IV = iv;

            using var decryptor = aes.CreateDecryptor();
            var plainBytes = decryptor.TransformFinalBlock(cipher, 0, cipher.Length);

            return Encoding.UTF8.GetString(plainBytes);
        }

        public static byte[] GenerateRandomKey()
        {
            var key = new byte[32];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(key);
            return key;
        }
    }
}
