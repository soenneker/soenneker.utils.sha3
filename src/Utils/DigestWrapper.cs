using Org.BouncyCastle.Crypto;
using Soenneker.Utils.SHA3.Utils.Abstract;
using System;
using System.Buffers;

namespace Soenneker.Utils.SHA3.Utils;

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

        byte[] rented = ArrayPool<byte>.Shared.Rent(data.Length);
        try
        {
            data.CopyTo(rented);
            _digest.BlockUpdate(rented, 0, data.Length);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented, clearArray: true);
        }
    }

    public byte[] Finish()
    {
        var hash = new byte[_digest.GetDigestSize()];
        _digest.DoFinal(hash, 0);
        return hash;
    }

    public void Dispose()
    {
        // No resources to dispose
    }
}