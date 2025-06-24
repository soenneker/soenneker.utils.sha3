using System;

namespace Soenneker.Utils.SHA3.Abstract;

internal interface IHashAggregator : IDisposable
{
    void Update(byte[] data);

    byte[] Finish();
}