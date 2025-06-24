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
    /// <summary>
    /// Computes the SHA3 hash of the given input string.
    /// </summary>
    /// <param name="input">The input string to hash.</param>
    /// <param name="log">Determines whether to log the hashing process.</param>
    /// <returns>The hexadecimal string representation of the hash.</returns>
    [Pure]
    string HashString(string input, bool log = true);

    /// <summary>
    /// Asynchronously computes the SHA3 hash of a file at the specified file path.
    /// </summary>
    /// <param name="filePath">The path to the file to hash.</param>
    /// <param name="log">Determines whether to log the hashing process.</param>
    /// <param name="cancellationToken">A token to monitor for cancellation requests.</param>
    /// <returns>A task representing the asynchronous operation. The result contains the hexadecimal string representation of the hash.</returns>
    [Pure]
    ValueTask<string> HashFile(string filePath, bool log = true, CancellationToken cancellationToken = default);

    [Pure]
    ValueTask<string> HashDirectory(string directoryPath, bool log = true, CancellationToken cancellationToken = default);
}