using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Soenneker.Extensions.Arrays.Bytes;
using Soenneker.Extensions.ValueTask;
using Soenneker.Utils.Directory.Abstract;
using Soenneker.Utils.SHA3.Abstract;
using Soenneker.Utils.SHA3.Utils;
using Soenneker.Utils.SHA3.Utils.Abstract;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Soenneker.Utils.SHA3;

/// <inheritdoc cref="ISha3Util"/>
public sealed class Sha3Util : ISha3Util
{
    private readonly ILogger<Sha3Util> _logger;
    private readonly IDirectoryUtil _directoryUtil;

    // Bigger read buffer tends to reduce syscalls for large files
    private const int _fileReadBufferSize = 128 * 1024;

    // FileStream internal buffer (81920 is the typical default; keep it)
    private const int _streamBufferSize = 81_920;

    public Sha3Util(ILogger<Sha3Util> logger, IDirectoryUtil directoryUtil)
    {
        _logger = logger;
        _directoryUtil = directoryUtil;
    }

    public string HashString(string input, bool log = true)
    {
        byte[] hash = HashStringBytes(input, log);
        return hash.ToHex();
    }

    public async ValueTask<string> HashFile(string filePath, bool log = true, CancellationToken cancellationToken = default)
    {
        byte[] hash = await HashFileBytes(filePath, log, cancellationToken)
            .NoSync();
        return hash.ToHex();
    }

    public async ValueTask<string> HashDirectory(string directoryPath, bool log = true, CancellationToken cancellationToken = default)
    {
        bool doLog = log && _logger.IsEnabled(LogLevel.Debug);

        if (doLog)
            _logger.LogDebug("Hashing all files in directory ({DirectoryPath})...", directoryPath);

        // Keep stable ordering for deterministic directory hashes
        List<string> filePaths = await _directoryUtil.GetFilesByExtension(directoryPath, "", true, cancellationToken);
        filePaths.Sort(StringComparer.Ordinal);

        if (doLog)
            _logger.LogDebug("Found {FileCount} files to hash in directory ({DirectoryPath})", filePaths.Count, directoryPath);

        if (filePaths.Count == 0)
            return string.Empty;

        using IHashAggregator hashAggregator = CreateAggregator();

        foreach (string filePath in filePaths)
        {
            cancellationToken.ThrowIfCancellationRequested();

            // IMPORTANT: hash bytes directly (no hex string round trip)
            byte[] fileHash = await HashFileBytes(filePath, log: false, cancellationToken)
                .NoSync();

            string relativePath = System.IO.Path.GetRelativePath(directoryPath, filePath);

            // Feed path bytes without allocating a new byte[] each time when possible
            int pathByteCount = Encoding.UTF8.GetByteCount(relativePath);
            byte[] pathBuffer = ArrayPool<byte>.Shared.Rent(pathByteCount);

            try
            {
                int written = Encoding.UTF8.GetBytes(relativePath, 0, relativePath.Length, pathBuffer, 0);

                hashAggregator.Update(pathBuffer.AsSpan(0, written));
                hashAggregator.Update(fileHash);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(pathBuffer, clearArray: true);
            }
        }

        return hashAggregator.Finish()
                             .ToHex();
    }

    private static IHashAggregator CreateAggregator()
    {
        if (Shake256.IsSupported)
            return new IncrementalHashWrapper(IncrementalHash.CreateHash(HashAlgorithmName.SHA3_256));

        return new DigestWrapper(new Sha3Digest(256));
    }

    private byte[] HashStringBytes(string input, bool log)
    {
        if (Shake256.IsSupported)
            return HashStringHardwareBytes(input, log);

        return ComputeHashBouncyBytes(input, new Sha3Digest(256), log);
    }

    private byte[] HashStringHardwareBytes(string input, bool log)
    {
        bool doLog = log && _logger.IsEnabled(LogLevel.Debug);
        if (doLog)
            _logger.LogDebug("SHA3 hardware hashing is supported, so using System.Security.Cryptography...");

        int byteCount = Encoding.UTF8.GetByteCount(input);

        // Rent exact-ish size; avoid input.ToBytes() allocation
        byte[] rented = ArrayPool<byte>.Shared.Rent(byteCount);

        try
        {
            int written = Encoding.UTF8.GetBytes(input, 0, input.Length, rented, 0);

            // Prefer span-based input if available
            return Shake256.HashData(rented.AsSpan(0, written), 256);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented, clearArray: true);
        }
    }

    private async ValueTask<byte[]> HashFileBytes(string filePath, bool log, CancellationToken cancellationToken)
    {
        if (Shake256.IsSupported)
            return await HashFileHardwareBytes(filePath, log, cancellationToken)
                .NoSync();

        return await ComputeFileHashBouncyBytes(filePath, new Sha3Digest(256), log, cancellationToken)
            .NoSync();
    }

    private async ValueTask<byte[]> HashFileHardwareBytes(string filePath, bool log, CancellationToken cancellationToken)
    {
        bool doLog = log && _logger.IsEnabled(LogLevel.Debug);
        if (doLog)
            _logger.LogDebug("SHA3 hardware hashing is supported, using that...");

        // FileStreamOptions gives you SequentialScan on supported runtimes/OSes
        var options = new FileStreamOptions
        {
            Access = FileAccess.Read,
            Mode = FileMode.Open,
            Share = FileShare.Read,
            Options = FileOptions.Asynchronous | FileOptions.SequentialScan,
            BufferSize = _streamBufferSize
        };

        await using var stream = new FileStream(filePath, options);

        return await Shake256.HashDataAsync(stream, 256, cancellationToken)
                             .NoSync();
    }

    private async ValueTask<byte[]> ComputeFileHashBouncyBytes(string filePath, IDigest digest, bool log, CancellationToken cancellationToken)
    {
        bool doLog = log && _logger.IsEnabled(LogLevel.Debug);
        if (doLog)
            _logger.LogDebug("SHA3 hardware hashing is NOT supported, using BouncyCastle...");

        var options = new FileStreamOptions
        {
            Access = FileAccess.Read,
            Mode = FileMode.Open,
            Share = FileShare.Read,
            Options = FileOptions.Asynchronous | FileOptions.SequentialScan,
            BufferSize = _streamBufferSize
        };

        await using var stream = new FileStream(filePath, options);

        byte[] buffer = ArrayPool<byte>.Shared.Rent(_fileReadBufferSize);

        try
        {
            while (true)
            {
                int bytesRead = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken)
                                            .NoSync();
                if (bytesRead <= 0)
                    break;

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

    private byte[] ComputeHashBouncyBytes(string input, Sha3Digest digest, bool log)
    {
        bool doLog = log && _logger.IsEnabled(LogLevel.Debug);
        if (doLog)
            _logger.LogDebug("SHA3 hardware hashing is NOT supported, using BouncyCastle...");

        int byteCount = Encoding.UTF8.GetByteCount(input);
        byte[] rented = ArrayPool<byte>.Shared.Rent(byteCount);

        try
        {
            int written = Encoding.UTF8.GetBytes(input, 0, input.Length, rented, 0);

            digest.BlockUpdate(rented, 0, written);

            var hash = new byte[digest.GetDigestSize()];
            digest.DoFinal(hash, 0);

            return hash;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented, clearArray: true);
        }
    }
}