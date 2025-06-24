using System.Security.Cryptography;
using Soenneker.Utils.SHA3.Abstract;

namespace Soenneker.Utils.SHA3;

internal sealed class IncrementalHashWrapper : IHashAggregator
{
    private readonly IncrementalHash _incrementalHash;

    public IncrementalHashWrapper(IncrementalHash incrementalHash)
    {
        _incrementalHash = incrementalHash;
    }

    public void Update(byte[] data) => _incrementalHash.AppendData(data);

    public byte[] Finish() => _incrementalHash.GetHashAndReset();

    public void Dispose() => _incrementalHash.Dispose();
}