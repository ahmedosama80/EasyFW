using System;
using System.Linq;
using System.Security.Cryptography;

namespace EasyFW.Core
{
    /// <summary>Salted PBKDF2 (SHA-256) hashes, so the saved settings never hold the password itself.</summary>
    public static class Password
    {
        private const int Iterations = 120000, SaltBytes = 16, HashBytes = 32;

        public static string Hash(string password)
        {
            var salt = new byte[SaltBytes];
            using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(salt);
            return $"pbkdf2-sha256:{Iterations}:{Convert.ToBase64String(salt)}:{Convert.ToBase64String(Derive(password, salt, Iterations))}";
        }

        public static bool Verify(string password, string stored)
        {
            var parts = (stored ?? "").Split(':');
            if (parts.Length != 4 || parts[0] != "pbkdf2-sha256" || !int.TryParse(parts[1], out var iterations)) return false;
            byte[] salt, expected;
            try
            {
                salt = Convert.FromBase64String(parts[2]);
                expected = Convert.FromBase64String(parts[3]);
            }
            catch (FormatException) { return false; }
            var actual = Derive(password ?? "", salt, iterations);
            // Compares every byte, so the time taken doesn't hint at how much matched.
            var diff = actual.Length ^ expected.Length;
            for (var i = 0; i < Math.Min(actual.Length, expected.Length); i++) diff |= actual[i] ^ expected[i];
            return diff == 0;
        }

        private static byte[] Derive(string password, byte[] salt, int iterations)
        {
            using var kdf = new Rfc2898DeriveBytes(password, salt, iterations, HashAlgorithmName.SHA256);
            return kdf.GetBytes(HashBytes);
        }
    }
}
