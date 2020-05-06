namespace Cryptography.Hashing
{
    using System;
    using System.Security.Cryptography;

    class SimpleSaltedHash
    {
        private const int SALT_SIZE = 8; // 64 bit

        private static RandomNumberGenerator RNG { get; } = RandomNumberGenerator.Create();

        public static byte[] Create(string plaintext)
        {
            var salt = GetRandomSalt(SALT_SIZE);
            var saltedPlaintext = $"{Convert.ToBase64String(salt)}:{plaintext}";

            var hash = SimpleHash.Create(saltedPlaintext);

            // create a new array to store <salt><hash>
            byte[] hashWithSalt = new byte[SALT_SIZE + hash.Length];

            // copy salt to the front of the array
            salt.CopyTo(hashWithSalt, 0);

            // copy hash after salt
            hash.CopyTo(hashWithSalt, SALT_SIZE);
            
            return hashWithSalt;
        }

        public static bool Verify(byte[] hashWithSalt, string plaintext, bool verbose = false)
        {
            // retrieve the salt from the given array
            var salt = hashWithSalt.AsSpan().Slice(0, SALT_SIZE).ToArray();
            var saltedPlaintext = $"{Convert.ToBase64String(salt)}:{plaintext}";

            var newHash = SimpleHash.Create(saltedPlaintext);

            // create a new array to store <salt><hash>
            byte[] newHashWithSalt = new byte[SALT_SIZE + newHash.Length];

            // copy salt, then hash
            salt.CopyTo(newHashWithSalt, 0);
            newHash.CopyTo(newHashWithSalt, SALT_SIZE);

            // if the given hashWithSalt equals the new hash we computed with the given salt and plaintext,
            // the hashes match.
            return Convert.ToBase64String(newHashWithSalt) == Convert.ToBase64String(hashWithSalt);
        }

        private static byte[] GetRandomSalt(int size)
        {
            byte[] salt = new byte[size];
            RNG.GetBytes(salt);

            return salt;
        }
    }
}
