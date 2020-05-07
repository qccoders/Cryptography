namespace Cryptography
{
    using System;
    using System.Security.Cryptography;
    using System.Text;

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

        public static string Md5(this string text)
        {
            using var md5 = MD5.Create();
            byte[] data = md5.ComputeHash(Encoding.UTF8.GetBytes(text));

            StringBuilder builder = new StringBuilder();

            for (int i = 0; i < data.Length; i++)
            {
                builder.Append(data[i].ToString("x2"));
            }

            return builder.ToString();
        }

        public static string Sha1(this string input)
        {
            using (SHA1Managed sha1 = new SHA1Managed())
            {
                var hash = sha1.ComputeHash(Encoding.UTF8.GetBytes(input));
                var sb = new StringBuilder(hash.Length * 2);

                foreach (byte b in hash)
                {
                    sb.Append(b.ToString("x2"));
                }

                return sb.ToString();
            }
        }

        public static string Sha256(this string input)
        {
            using (SHA256Managed sha1 = new SHA256Managed())
            {
                var hash = sha1.ComputeHash(Encoding.UTF8.GetBytes(input));
                var sb = new StringBuilder(hash.Length * 2);

                foreach (byte b in hash)
                {
                    sb.Append(b.ToString("x2"));
                }

                return sb.ToString();
            }
        }

        public static string Sha512(this string input)
        {
            using (SHA512Managed sha1 = new SHA512Managed())
            {
                var hash = sha1.ComputeHash(Encoding.UTF8.GetBytes(input));
                var sb = new StringBuilder(hash.Length * 2);

                foreach (byte b in hash)
                {
                    sb.Append(b.ToString("x2"));
                }

                return sb.ToString();
            }
        }
    }
}
