using System;
using Argon2.NetCore;
using PinnedMemory;
using Xunit;

namespace Argon2.NetCore.Tests;

public class Argon2Rfc9106VectorsTests
{
    [Fact]
    public void Argon2d_Matches_Rfc9106_Section5_1_TestVector()
    {
        // Source: RFC 9106, section 5.1 "Argon2d Test Vectors"
        // https://www.rfc-editor.org/rfc/rfc9106.html#section-5.1
        var output = DeriveHash(Argon2.AddressType.DependentAddressing);

        Assert.Equal(
            "512B391B6F1162975371D30919734294F868E3BE3984F3C1A13A4DB9FABE4ACB",
            Convert.ToHexString(output));
    }

    [Fact]
    public void Argon2i_Matches_Rfc9106_Section5_2_TestVector()
    {
        // Source: RFC 9106, section 5.2 "Argon2i Test Vectors"
        // https://www.rfc-editor.org/rfc/rfc9106.html#section-5.2
        var output = DeriveHash(Argon2.AddressType.IndependentAddressing);

        Assert.Equal(
            "C814D9D1DC7F37AA13F0D77F2494BDA1C8DE6B016DD388D29952A4C4672B6CE8",
            Convert.ToHexString(output));
    }

    private static byte[] DeriveHash(Argon2.AddressType addressing)
    {
        // RFC 9106 vector inputs:
        // P=0x01 repeated 32 times, S=0x02 repeated 16 times,
        // K=0x03 repeated 8 times, X=0x04 repeated 12 times,
        // t=3, m=32 KiB, p=4, tagLength=32.
        var password = Repeat(0x01, 32);
        var salt = Repeat(0x02, 16);
        var secret = Repeat(0x03, 8);
        var associatedData = Repeat(0x04, 12);

        using var secretPin = new PinnedMemory<byte>(secret, false);
        using var argon2 = new Argon2(secretPin, salt, associatedData)
        {
            Addressing = addressing,
            HashLength = 32,
            MemoryCost = 32,
            TimeCost = 3,
            Lanes = 4,
            Threads = 1,
        };

        argon2.UpdateBlock(password, 0, password.Length);

        var output = new byte[argon2.GetLength()];
        using var outputPin = new PinnedMemory<byte>(new byte[argon2.GetLength()]);
        argon2.DoFinal(outputPin, 0);
        Array.Copy(outputPin.ToArray(), output, output.Length);

        return output;
    }

    private static byte[] Repeat(byte value, int count)
    {
        var output = new byte[count];
        Array.Fill(output, value);
        return output;
    }
}
