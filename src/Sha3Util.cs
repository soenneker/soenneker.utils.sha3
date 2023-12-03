using Soenneker.Utils.SHA3.Abstract;
using System.Security.Cryptography;
using System.IO;
using System.Threading.Tasks;
using Soenneker.Extensions.ByteArray;
using Soenneker.Extensions.String;
using Soenneker.Extensions.ValueTask;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;

namespace Soenneker.Utils.SHA3;

/// <inheritdoc cref="ISha3Util"/>
public class Sha3Util : ISha3Util
{
    public Sha3Util()
    {
    }

    public static string HashString(string input)
    {
        string result;

        if (Shake256.IsSupported)
        {
            result = HashStringHardware(input);
            return result;
        }

        result = ComputeHashBouncy(input, new Sha3Digest(256));
        return result;
    }

    private static string HashStringHardware(string input)
    {
        byte[] bytes = input.ToBytes();

        byte[] hashed = Shake256.HashData(bytes, 256);

        string result = hashed.ToStr();

        return result;
    }

    public static async ValueTask<string> HashFile(string filePath)
    {
        string result;

        if (Shake256.IsSupported)
        {
            result = (await HashFileHardware(filePath)).ToStr();
            return result;
        }

        result = await ComputeFileHashBouncy(filePath, new Sha3Digest(256));
        return result;
    }

    private static async ValueTask<byte[]> HashFileHardware(string filePath)
    {
        await using (var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read))
        {
            byte[] result = await Shake256.HashDataAsync(stream, 256).NoSync();
            return result;
        }
    }

    private static async ValueTask<string> ComputeFileHashBouncy(string filePath, IDigest digest)
    {
        await using (Stream stream = new FileStream(filePath, FileMode.Open, FileAccess.Read))
        {
            var buffer = new byte[8192];
            int bytesRead;

            while ((bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length)) > 0)
            {
                digest.BlockUpdate(buffer, 0, bytesRead);
            }

            var hash = new byte[digest.GetDigestSize()];
            digest.DoFinal(hash, 0);

            var result = new StringBuilder(hash.Length * 2);

            foreach (byte b in hash)
            {
                result.AppendFormat("{0:x2}", b);
            }

            return result.ToString();
        }
    }

    private static string ComputeHashBouncy(string input, IDigest digest)
    {
        byte[] data = input.ToBytes();
        digest.BlockUpdate(data, 0, data.Length);

        var hash = new byte[digest.GetDigestSize()];
        digest.DoFinal(hash, 0);

        // Convert the byte array to a hexadecimal string
        var result = new StringBuilder(hash.Length * 2);

        foreach (byte b in hash)
        {
            result.AppendFormat("{0:x2}", b);
        }

        return result.ToString();
    }
}