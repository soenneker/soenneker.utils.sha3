using System;
using Soenneker.Utils.SHA3.Abstract;
using System.Security.Cryptography;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Soenneker.Extensions.String;
using Soenneker.Extensions.ValueTask;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Soenneker.Extensions.Arrays.Bytes;
using System.Buffers;
using System.Text;

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

        return bytes.ToHex();
    }

    private byte[] HashStringHardware(string input, bool log)
    {
        if (log)
            _logger.LogDebug("SHA3 hardware hashing is supported, so using System.Security.Cryptography...");

        byte[] bytes = input.ToBytes();

        return Shake256.HashData(bytes, 256);
    }

    public async ValueTask<string> HashFile(string filePath, bool log = true, CancellationToken cancellationToken = default)
    {
        byte[] bytes;

        if (Shake256.IsSupported)
            bytes = await HashFileHardware(filePath, log, cancellationToken).NoSync();
        else
            bytes = await ComputeFileHashBouncy(filePath, new Sha3Digest(256), log, cancellationToken).NoSync();

        return bytes.ToHex();
    }

    private async ValueTask<byte[]> HashFileHardware(string filePath, bool log, CancellationToken cancellationToken)
    {
        if (log)
            _logger.LogDebug("SHA3 hardware hashing is supported, using that...");

        // Open the file stream with buffer size for improved performance
        await using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read, bufferSize: 81920, options: FileOptions.Asynchronous);

        // Perform hashing with the stream
        return await Shake256.HashDataAsync(stream, 256, cancellationToken).NoSync();
    }

    private async ValueTask<byte[]> ComputeFileHashBouncy(string filePath, IDigest digest, bool log, CancellationToken cancellationToken)
    {
        if (log)
            _logger.LogDebug("SHA3 hardware hashing is NOT supported, using BouncyCastle...");

        // Use a pre-allocated buffer and FileStream with optimal settings
        await using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read, bufferSize: 81920, options: FileOptions.Asynchronous);

        byte[] buffer = ArrayPool<byte>.Shared.Rent(8192); // Use ArrayPool to reduce allocations

        try
        {
            int bytesRead;
            while ((bytesRead = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken).NoSync()) > 0)
            {
                digest.BlockUpdate(buffer, 0, bytesRead);
            }

            var hash = new byte[digest.GetDigestSize()];
            digest.DoFinal(hash, 0);
            return hash;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
        }
    }

    private byte[] ComputeHashBouncy(string input, Sha3Digest digest, bool log)
    {
        if (log)
            _logger.LogDebug("SHA3 hardware hashing is NOT supported, using BouncyCastle...");

        // Use ArrayPool to minimize allocations for byte conversion
        byte[] inputBytes = ArrayPool<byte>.Shared.Rent(input.Length * sizeof(char));

        try
        {
            int byteCount = Encoding.UTF8.GetBytes(input, 0, input.Length, inputBytes, 0);

            digest.BlockUpdate(inputBytes, 0, byteCount);

            // Compute the final hash
            var hash = new byte[digest.GetDigestSize()];
            digest.DoFinal(hash, 0);

            return hash;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(inputBytes, clearArray: true);
        }
    }
}