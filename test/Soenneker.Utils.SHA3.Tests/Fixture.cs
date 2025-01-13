using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Serilog;
using Soenneker.Fixtures.Unit;
using Soenneker.Utils.SHA3.Registrars;
using Soenneker.Utils.Test;

namespace Soenneker.Utils.SHA3.Tests;

public class Fixture : UnitFixture
{
    public override async System.Threading.Tasks.ValueTask InitializeAsync()
    {
        SetupIoC(Services);

        await base.InitializeAsync();
    }

    private static void SetupIoC(IServiceCollection services)
    {
        services.AddLogging(builder => { builder.AddSerilog(dispose: true); });

        IConfiguration config = TestUtil.BuildConfig();
        services.AddSingleton(config);

        services.AddSha3UtilAsScoped();
    }
}