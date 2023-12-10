using Soenneker.Utils.SHA3.Abstract;
using System.Security.Cryptography;
using System.IO;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Soenneker.Extensions.ByteArray;
using Soenneker.Extensions.String;
using Soenneker.Extensions.ValueTask;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Soenneker.Extensions.Task;

namespace Soenneker.Utils.SHA3;

/// <inheritdoc cref="ISha3Util"/>
public class Sha3Util : ISha3Util
{
    private readonly ILogger<Sha3Util> _logger;

    public Sha3Util(ILogger<Sha3Util> logger)
    {
        _logger = logger;
    }

    public string HashString(string input, bool log = true)
    {
        byte[] bytes;

        if (Shake256.IsSupported)
            bytes = HashStringHardware(input, log);
        else
            bytes = ComputeHashBouncy(input, new Sha3Digest(256), log);

        string result = bytes.ToHex();
        return result;
    }

    private byte[] HashStringHardware(string input, bool log)
    {
        if (log)
            _logger.LogDebug("SHA3 hardware hashing is supported, so using System.Security.Cryptography...");

        byte[] bytes = input.ToBytes();

        byte[] hashed = Shake256.HashData(bytes, 256);

        return hashed;
    }

    public async ValueTask<string> HashFile(string filePath, bool log = true)
    {
        byte[] bytes;

        if (Shake256.IsSupported)
            bytes = await HashFileHardware(filePath, log).NoSync();
        else
            bytes = await ComputeFileHashBouncy(filePath, new Sha3Digest(256), log).NoSync();

        string result = bytes.ToHex();
        return result;
    }

    private async ValueTask<byte[]> HashFileHardware(string filePath, bool log)
    {
        if (log)
            _logger.LogDebug("SHA3 hardware hashing is supported, so using that...");

        await using (var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read))
        {
            byte[] result = await Shake256.HashDataAsync(stream, 256).NoSync();
            return result;
        }
    }

    private async ValueTask<byte[]> ComputeFileHashBouncy(string filePath, IDigest digest, bool log)
    {
        if (log)
            _logger.LogDebug("SHA3 hardware hashing is NOT supported, so using BouncyCastle...");

        await using (var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read))
        {
            var buffer = new byte[8192];
            int bytesRead;

            while ((bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length).NoSync()) > 0)
            {
                digest.BlockUpdate(buffer, 0, bytesRead);
            }

            var hash = new byte[digest.GetDigestSize()];
            digest.DoFinal(hash, 0);

            return hash;
        }
    }

    private byte[] ComputeHashBouncy(string input, IDigest digest, bool log)
    {
        if (log)
            _logger.LogDebug("SHA3 hardware hashing is NOT supported, so using BouncyCastle...");

        byte[] data = input.ToBytes();
        digest.BlockUpdate(data, 0, data.Length);

        var hash = new byte[digest.GetDigestSize()];
        digest.DoFinal(hash, 0);

        return hash;
    }
}