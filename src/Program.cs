﻿namespace Cryptography
{
    using Cryptography.Hashing;
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using Utility.CommandLine;

    class Program
    {
        [Operands]
        private static List<string> Operands { get; set; }

        static void Log(string s = "") => Console.WriteLine(s);
        
        static void Main(string[] args)
        {
            Arguments.Populate();

            string command = "simple-hash";
            string input = "Hello, World!";

            if (Operands.Count > 1)
            {
                command = Operands[1];
            }

            if (Operands.Count > 2)
            {
                input = string.Join(" ", Operands.Skip(2));
            }

            Log();

            switch (command)
            {
                case "simple-hash":
                    {
                        var hash = SimpleHash.Create(input, verbose: true);
                        Log($"Hex: {hash.Hex()}");
                        Log($"Base64: {hash.Base64()}");
                        return;
                    }
                case "simple-salted-hash":
                    {
                        var simpleSalted = new List<byte[]>();

                        for (int i = 0; i < 5; i++)
                        {
                            simpleSalted.Add(SimpleSaltedHash.Create(input));
                        }

                        simpleSalted.ForEach(s => Log($"Simple Salted Hash: {s.Base64()}"));

                        Log();

                        foreach (var hash in simpleSalted)
                        {
                            Log($"Hash: {hash.Base64()}\tValid: {SimpleSaltedHash.Verify(hash, input)}");
                        }
                        return;
                    }
                case "md5":
                    {
                        Log($"MD5: {input.Md5()}");
                        return;
                    }
                case "sha":
                    {
                        Log($"SHA1: {input.Sha1()}");
                        Log($"SHA256: {input.Sha256()}");
                        Log($"SHA512: {input.Sha512()}");
                        return;
                    }
                case "hash-password":
                    {
                        var hashes = new List<byte[]>();

                        for (int i = 0; i < 5; i++)
                        {
                            hashes.Add(PasswordHasher.HashPassword(input));
                        }

                        hashes.ForEach(s => Log($"Password Hash: {s.Base64()}"));

                        Log();

                        foreach (var hash in hashes)
                        {
                            Log($"Hash: {hash.Base64()}\tValid: {PasswordHasher.VerifyPassword(input, hash)}");
                        }

                        return;
                    }
                default:
                    Log($"Unknown command {command}");
                    return;
            }
        }
    }
}
