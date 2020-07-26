using System;
using System.Security.Cryptography;
using PinnedMemory;

namespace Argon2.NetCore.Examples
{
    class Program
    {
        static void Main(string[] args)
        {
            var iv = new byte[16];
            var key = new byte[32];

            using var provider = new RNGCryptoServiceProvider();
            provider.GetBytes(iv);
            provider.GetBytes(key);

            using var keyPin = new PinnedMemory<byte>(key, false);
            using var argon2 = new Argon2(keyPin, iv)
            {
                Addressing = Argon2.AddressType.DependentAddressing,
                HashLength = 64,
                MemoryCost = 65536,
                Lanes = 4,
                Threads = 2,
                TimeCost = 3
            };

            argon2.UpdateBlock(new PinnedMemory<byte>(new byte[] {63, 61, 77, 20, 63, 61, 77, 20, 63, 61, 77}, false),
                0, 11); // caw caw caw in utf8

            using var hash = new PinnedMemory<byte>(new byte[argon2.GetLength()]);
            argon2.DoFinal(hash, 0);

            Console.WriteLine(BitConverter.ToString(hash.ToArray()));
        }
    }
}
