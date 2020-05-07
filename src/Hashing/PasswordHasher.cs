namespace Cryptography.Hashing
{
    using Microsoft.AspNetCore.Cryptography.KeyDerivation;
    using System;
    using System.Security.Cryptography;

    public static class PasswordHasher
    {
        private const int SALT_LENGTH = 16;
        private const int HASH_LENGTH = 36;
        private const int ITERATIONS = 1000;

        private static RandomNumberGenerator RNG { get; } = new RNGCryptoServiceProvider();

        public static byte[] HashPassword(string password)
        {
            byte[] salt = new byte[SALT_LENGTH];
            RNG.GetBytes(salt);

            var hash = KeyDerivation.Pbkdf2(password, salt, KeyDerivationPrf.HMACSHA256, iterationCount: ITERATIONS, numBytesRequested: HASH_LENGTH);

            var outputBytes = new byte[salt.Length + hash.Length];
            salt.CopyTo(outputBytes, 0);
            hash.CopyTo(outputBytes, salt.Length);

            return outputBytes;
        }

        public static bool VerifyPassword(string password, byte[] hash)
        {
            var salt = hash.AsSpan().Slice(0, SALT_LENGTH).ToArray();
            hash = hash.AsSpan().Slice(SALT_LENGTH, HASH_LENGTH).ToArray();

            var newHash = KeyDerivation.Pbkdf2(password, salt, KeyDerivationPrf.HMACSHA256, iterationCount: ITERATIONS, numBytesRequested: HASH_LENGTH);

            return hash.Base64() == newHash.Base64();
        }
    }
}
