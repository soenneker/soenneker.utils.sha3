using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Soenneker.Utils.SHA3.Abstract;

namespace Soenneker.Utils.SHA3.Registrars;

/// <summary>
/// A utility library for SHA-3 hashing
/// </summary>
public static class Sha3UtilRegistrar
{
    /// <summary>
    /// Adds <see cref="ISha3Util"/> as a singleton service. <para/>
    /// </summary>
    public static void AddSha3UtilAsSingleton(this IServiceCollection services)
    {
        services.TryAddSingleton<ISha3Util, Sha3Util>();
    }

    /// <summary>
    /// Adds <see cref="ISha3Util"/> as a scoped service. <para/>
    /// </summary>
    public static void AddSha3UtilAsScoped(this IServiceCollection services)
    {
        services.TryAddScoped<ISha3Util, Sha3Util>();
    }
}