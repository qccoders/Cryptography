namespace Cryptography
{
    using Cryptography.Hashing;
    using System;

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

            var simple = SimpleHash.Create(input);
        }
    }
}
