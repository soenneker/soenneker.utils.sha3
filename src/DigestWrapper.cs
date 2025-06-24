using Org.BouncyCastle.Crypto;
using Soenneker.Utils.SHA3.Abstract;

namespace Soenneker.Utils.SHA3;

public sealed class DigestWrapper : IHashAggregator
{
    private readonly IDigest _digest;

    public DigestWrapper(IDigest digest)
    {
        _digest = digest;
    }

    public void Update(byte[] data) => _digest.BlockUpdate(data, 0, data.Length);

    public byte[] Finish()
    {
        var hash = new byte[_digest.GetDigestSize()];
        _digest.DoFinal(hash, 0);
        return hash;
    }

    public void Dispose()
    {
    }
}