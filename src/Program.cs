namespace Cryptography
{
    using Cryptography.Hashing;
    using System;
    using System.Collections.Generic;

    class Program
    {
        static void Log(string s) => Console.WriteLine(s);
        static void Section(string s) => Console.WriteLine($"-------------------------\n{s}\n");
        
        static void Main(string[] args)
        {
            var input = string.Join(" ", args);
            input = string.IsNullOrEmpty(input) ? "Hello, World!" : input;
            
            Log($"\nInput: {input}\n");

            Section("Simple Hash");

            var simple = SimpleHash.Create(input, verbose: true);

            Section("Simple Salted Hash");

            var simpleSalted = new List<byte[]>();

            for (int i = 0; i < 5; i++)
            {
                simpleSalted.Add(SimpleSaltedHash.Create(input));
            }

            simpleSalted.ForEach(s => Console.WriteLine($"Simple Salted Hash: {Convert.ToBase64String(s)}"));
            
            Section("Simple Salted Hash Validation");

            foreach (var hash in simpleSalted)
            {
                Console.WriteLine($"Hash: {Convert.ToBase64String(hash)}\tValid: {SimpleSaltedHash.Verify(hash, input)}");
            }
        }
    }
}
