using Org.BouncyCastle.Crypto;
using Soenneker.Utils.SHA3.Utils.Abstract;
using System;
using System.Buffers;

namespace Soenneker.Utils.SHA3.Utils;

/// <inheritdoc cref="IHashAggregator"/>
public sealed class DigestWrapper : IHashAggregator
{
    private readonly IDigest _digest;

    public DigestWrapper(IDigest digest)
    {
        _digest = digest;
    }

    public void Update(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty)
            return;

        byte[] rented = ArrayPool<byte>.Shared.Rent(Math.Min(data.Length, 16 * 1024));
        try
        {
            while (!data.IsEmpty)
            {
                int count = Math.Min(data.Length, rented.Length);
                data[..count].CopyTo(rented);
                _digest.BlockUpdate(rented, 0, count);
                data = data[count..];
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented, clearArray: true);
        }
    }

    public void Update(byte[] data, int offset, int count)
    {
        if (count == 0)
            return;

        _digest.BlockUpdate(data, offset, count);
    }

    public byte[] Finish()
    {
        var hash = new byte[_digest.GetDigestSize()];
        _digest.DoFinal(hash, 0);
        return hash;
    }

    /// <summary>
    /// Releases resources used by the current instance.
    /// </summary>
    public void Dispose()
    {
        // No resources to dispose
    }
}
