using System;

namespace Soenneker.Utils.SHA3.Utils.Abstract;

/// <summary>
/// Defines the hash aggregator contract.
/// </summary>
public interface IHashAggregator : IDisposable
{
    /// <summary>
    /// Executes the update operation.
    /// </summary>
    /// <param name="data">The data.</param>
    void Update(ReadOnlySpan<byte> data);

    /// <summary>
    /// Updates the hash from an array segment without requiring span-only implementations
    /// to allocate an intermediate array.
    /// </summary>
    void Update(byte[] data, int offset, int count) => Update(data.AsSpan(offset, count));

    /// <summary>
    /// Executes the finish operation.
    /// </summary>
    /// <returns>The result of the operation.</returns>
    byte[] Finish();
}
