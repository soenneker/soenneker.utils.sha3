using Soenneker.Utils.SHA3.Utils.Abstract;
using System;
using System.Security.Cryptography;

namespace Soenneker.Utils.SHA3.Utils;

internal sealed class IncrementalHashWrapper : IHashAggregator
{
    private readonly IncrementalHash _incrementalHash;

    public IncrementalHashWrapper(IncrementalHash incrementalHash)
    {
        _incrementalHash = incrementalHash;
    }

    public void Update(ReadOnlySpan<byte> data) => _incrementalHash.AppendData(data);

    public byte[] Finish() => _incrementalHash.GetHashAndReset();

    public void Dispose() => _incrementalHash.Dispose();
}