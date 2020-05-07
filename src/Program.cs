namespace Cryptography
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

                        simpleSalted.ForEach(s => Console.WriteLine($"Simple Salted Hash: {Convert.ToBase64String(s)}"));

                        Log();

                        foreach (var hash in simpleSalted)
                        {
                            Console.WriteLine($"Hash: {Convert.ToBase64String(hash)}\tValid: {SimpleSaltedHash.Verify(hash, input)}");
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
