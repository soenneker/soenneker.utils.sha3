using System;

namespace Soenneker.Utils.SHA3.Utils.Abstract;

/// <summary>
/// Defines the hash aggregator contract.
/// </summary>
public interface IHashAggregator : IDisposable
{
    /// <summary>
    /// Adds the supplied bytes to the incremental hash state.
    /// </summary>
    /// <param name="data">The next bytes added to the hash.</param>
    void Update(ReadOnlySpan<byte> data);

    /// <summary>
    /// Updates the hash from an array segment without requiring span-only implementations
    /// to allocate an intermediate array.
    /// </summary>
    void Update(byte[] data, int offset, int count) => Update(data.AsSpan(offset, count));

    /// <summary>
    /// Finalizes the incremental hash and returns its digest.
    /// </summary>
    /// <returns>The finalized digest bytes.</returns>
    byte[] Finish();
}
