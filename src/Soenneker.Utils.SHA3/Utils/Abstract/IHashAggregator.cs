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
    /// Executes the finish operation.
    /// </summary>
    /// <returns>The result of the operation.</returns>
    byte[] Finish();
}