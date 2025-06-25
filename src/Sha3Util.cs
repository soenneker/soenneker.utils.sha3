using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Soenneker.Extensions.Arrays.Bytes;
using Soenneker.Extensions.String;
using Soenneker.Extensions.ValueTask;
using Soenneker.Utils.SHA3.Abstract;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Soenneker.Utils.SHA3;

/// <inheritdoc cref="ISha3Util"/>
public sealed class Sha3Util : ISha3Util
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

    public async ValueTask<string> HashDirectory(string directoryPath, bool log = true, CancellationToken cancellationToken = default)
    {
        if (log)
            _logger.LogDebug("Hashing all files in directory ({DirectoryPath})...", directoryPath);

        List<string> filePaths = Directory.EnumerateFiles(directoryPath, "*", SearchOption.AllDirectories).OrderBy(p => p, StringComparer.Ordinal).ToList();

        if (log)
            _logger.LogDebug("Found {FileCount} files to hash in directory ({DirectoryPath})", filePaths.Count, directoryPath);

        if (filePaths.Count == 0)
            return string.Empty;

        IHashAggregator hashAggregator;

        if (Shake256.IsSupported)
        {
            hashAggregator = new IncrementalHashWrapper(IncrementalHash.CreateHash(HashAlgorithmName.SHA3_256));
        }
        else
        {
            hashAggregator = new DigestWrapper(new Sha3Digest(256));
        }

        foreach (string filePath in filePaths)
        {
            cancellationToken.ThrowIfCancellationRequested();

            string fileHashHex = await HashFile(filePath, log: false, cancellationToken).NoSync();
            byte[] fileHash = fileHashHex.ToBytesFromHex();

            string relativePath = Path.GetRelativePath(directoryPath, filePath);
            byte[] pathBytes = relativePath.ToBytes();

            hashAggregator.Update(pathBytes);
            hashAggregator.Update(fileHash);
        }

        string result = hashAggregator.Finish().ToHex();

        hashAggregator.Dispose();

        return result;
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