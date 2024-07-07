using System.Diagnostics.Contracts;
using System.Threading;
using System.Threading.Tasks;

namespace Soenneker.Utils.SHA3.Abstract;

/// <summary>
/// A utility library for SHA-3 hashing. <para/>
/// Uses the new System.Cryptography SHA3 hardware implementation if available, otherwise uses BouncyCastle.
/// </summary>
public interface ISha3Util
{
    [Pure]
    string HashString(string input, bool log = true);

    [Pure]
    ValueTask<string> HashFile(string filePath, bool log = true, CancellationToken cancellationToken = default);
}