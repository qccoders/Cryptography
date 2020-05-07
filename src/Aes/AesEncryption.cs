namespace Cryptography.Aes
{
    using Microsoft.AspNetCore.Cryptography.KeyDerivation;
    using System;
    using System.IO;
    using System.Security.Cryptography;

    public static class AesEncryption
    {
        private const int KEY_SIZE = 256;
        private const int BLOCK_SIZE = 128;
        private const int KEYGEN_ITERATIONS = 1000;

        private static RandomNumberGenerator RNG { get; } = new RNGCryptoServiceProvider();

        public static byte[] Encrypt(string plainText, string password)
        {
            // get a key and the salt used to generate it
            var (secret, salt) = GenerateSecret(password);

            // get a random initialization vector
            var iv = GenerateRandomIV();

            byte[] cipher;

            using (var aes = Aes.Create())
            {
                aes.KeySize = KEY_SIZE;
                aes.BlockSize = BLOCK_SIZE;
                aes.Padding = PaddingMode.PKCS7;

                using (var encryptor = aes.CreateEncryptor(secret, iv))
                using (var memoryStream = new MemoryStream())
                using (var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                using (var streamWriter = new StreamWriter(cryptoStream))
                {
                    streamWriter.Write(plainText);
                    streamWriter.Close();

                    cipher = memoryStream.ToArray();
                }
            }

            // dimension an array to hold the iv, salt and cipher
            byte[] cipherWithIVAndSalt = new byte[iv.Length + salt.Length + cipher.Length];
            iv.CopyTo(cipherWithIVAndSalt, 0);
            salt.CopyTo(cipherWithIVAndSalt, iv.Length);
            cipher.CopyTo(cipherWithIVAndSalt, iv.Length + salt.Length);

            // <initialization vector><salt><cipher>
            return cipherWithIVAndSalt;
        }

        public static string Decrypt(byte[] cipherWithIVAndSalt, string password)
        {
            var span = cipherWithIVAndSalt.AsSpan();

            var blockSize = BLOCK_SIZE / 8;

            var iv = span.Slice(0, blockSize).ToArray();
            var salt = span.Slice(blockSize, blockSize).ToArray();
            var cipher = span.Slice(blockSize * 2, cipherWithIVAndSalt.Length - blockSize * 2).ToArray();

            var secret = RetrieveSecret(password, salt);

            using (var aes = Aes.Create())
            {
                aes.KeySize = KEY_SIZE;
                aes.BlockSize = BLOCK_SIZE;
                aes.Padding = PaddingMode.PKCS7;

                using (var decryptor = aes.CreateDecryptor(secret, iv))
                using (var memoryStream = new MemoryStream(cipher))
                using (var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                using (var streamReader = new StreamReader(cryptoStream))
                {
                    return streamReader.ReadToEnd();
                }
            }
        }

        private static byte[] GenerateRandomIV()
        {
            using (var aes = Aes.Create())
            {
                aes.KeySize = KEY_SIZE;
                aes.BlockSize = BLOCK_SIZE;

                aes.GenerateIV();

                return aes.IV;
            }
        }

        private static (byte[] Secret, byte[] Salt) GenerateSecret(string password)
        {
            byte[] salt = new byte[BLOCK_SIZE / 8];

            RNG.GetBytes(salt);
            return (KeyDerivation.Pbkdf2(password, salt, KeyDerivationPrf.HMACSHA256, KEYGEN_ITERATIONS, KEY_SIZE / 8), salt);
        }

        private static byte[] RetrieveSecret(string password, byte[] salt)
        {
            return KeyDerivation.Pbkdf2(password, salt, KeyDerivationPrf.HMACSHA256, KEYGEN_ITERATIONS, KEY_SIZE / 8);
        } 
    }
}
