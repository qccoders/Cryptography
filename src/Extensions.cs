namespace Cryptography
{
    using System;

    public static class Extensions
    {
        public static string Hex(this byte[] bytes)
        {
            return BitConverter.ToString(bytes);
        }

        public static string Base64(this byte[] bytes)
        {
            return Convert.ToBase64String(bytes);
        }
    }
}
