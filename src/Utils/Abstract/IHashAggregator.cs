using System;

namespace Soenneker.Utils.SHA3.Utils.Abstract;

public interface IHashAggregator : IDisposable
{
    void Update(ReadOnlySpan<byte> data);
    byte[] Finish();
}