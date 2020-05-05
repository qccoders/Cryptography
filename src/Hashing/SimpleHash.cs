namespace Cryptography.Hashing
{
    using System;
    using System.Text;

    class SimpleHash
    {
        private const int HASH_SIZE = 8; // 64 bit

        public static byte[] Create(string plaintext)
        {
            // initialize the hash to a properly sized byte array
            var hash = new byte[HASH_SIZE];

            // pad the input text to ensure that the resulting length is divisible evenly into HASH_SIZE byte chunks
            var adjustedLength = ((int)Math.Ceiling(plaintext.Length / (decimal)HASH_SIZE)) * HASH_SIZE;
            plaintext = plaintext.PadRight(adjustedLength, '-');

            // get the bytes from the plaintext string
            var plainbytes = Encoding.UTF8.GetBytes(plaintext).AsSpan();

            for (int i = 0; i < plainbytes.Length; i += HASH_SIZE)
            {
                // get the next 4 byte chunk from the padded plaintext
                var chunk = plainbytes.Slice(i, HASH_SIZE).ToArray();

                // xor the new chunk with the existing hash
                var newHash = Xor(hash, chunk);

                Console.WriteLine($"{BitConverter.ToString(hash)}\tXOR\t{BitConverter.ToString(chunk)}\t=\t{BitConverter.ToString(newHash)}");
                hash = newHash;
            }

            Console.WriteLine($"Computed Hash: {BitConverter.ToString(hash)}\tBase 64: {Convert.ToBase64String(hash)}");
            return hash;
        }

        private static byte[] Xor(byte[] left, byte[] right)
        {
            if (left.Length != right.Length)
            {
                throw new ArgumentException($"Left and right arrays must be of equal length; given {left.Length} and {right.Length}");
            }

            byte[] result = new byte[left.Length];

            for (int i = 0; i < left.Length; i++)
            {
                result[i] = (byte)(left[i] ^ right[i]);
            }

            return result;
        }
    }
}
