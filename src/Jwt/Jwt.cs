namespace Cryptography.Jwt
{
    using Microsoft.AspNetCore.Cryptography.KeyDerivation;
    using Microsoft.IdentityModel.Tokens;
    using System;
    using System.Collections.Generic;
    using System.IdentityModel.Tokens.Jwt;
    using System.Security.Claims;
    using System.Security.Cryptography;

    public static class JsonWebToken
    {
        public static (string Jwt, byte[] Secret) GetJwt(string password)
        {
            var issuedUtc = DateTime.UtcNow;
            var expiresUtc = DateTime.UtcNow.AddMilliseconds(86400000); // 24 hours

            var claims = new List<Claim>()
            {
                new Claim(ClaimTypes.Name, "QC Coders"),
                new Claim(ClaimTypes.NameIdentifier, Guid.NewGuid().ToString()),
                new Claim(ClaimTypes.Role, "User"),
                new Claim("name", "QC Coders"),
                new Claim("iat", ((DateTimeOffset)issuedUtc).ToUnixTimeSeconds().ToString())
            };

            var secret = GetSecret(password);
            var key = new SymmetricSecurityKey(secret);

            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: "slsk-web-example",
                claims: claims,
                notBefore: issuedUtc,
                expires: expiresUtc,
                signingCredentials: credentials);

            return (new JwtSecurityTokenHandler().WriteToken(token), secret);
        }

        private static byte[] GetSecret(string password)
        {
            byte[] salt = new byte[16];
            int iterations = 1000;

            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(salt);
                return KeyDerivation.Pbkdf2(password, salt, KeyDerivationPrf.HMACSHA256, iterations, 32);
            }
        }
    }
}
