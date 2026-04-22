using System.Threading.Tasks;
using AwesomeAssertions;
using Soenneker.Tests.Attributes.Local;
using Soenneker.Tests.HostedUnit;
using Soenneker.Utils.SHA3.Abstract;
using Soenneker.Utils.SHA3.Tests;


namespace Soenneker.Utils.Sha3.Tests.Utils;

[ClassDataSource<Host>(Shared = SharedType.PerTestSession)]
public class Sha3UtilTests : HostedUnitTest
{
    private readonly ISha3Util _util;

    public Sha3UtilTests(Host host) : base(host)
    {
        _util = Resolve<ISha3Util>();
    }

    [Test]
    public void HashString_should_hash_string()
    {
        string result = _util.HashString(Faker.Random.AlphaNumeric(20));
        result.Should().NotBeNullOrEmpty();
    }

    [Test]
    public void HashString_should_hash_string_consistently()
    {
        string? test = Faker.Random.AlphaNumeric(20);

        string result1 = _util.HashString(test);
        string result2 = _util.HashString(test);

        result1.Should().Be(result2);
    }

    [Test]
    public async Task HashFile_should_hash()
    {
        string result = await _util.HashFile(System.IO.Path.Combine("Resources", "testfile.txt"), true, CancellationToken);
        result.Should().NotBeNullOrEmpty();
    }

    [LocalOnly]
    public async Task HashDirectory_should_hash()
    {
        string result = await _util.HashDirectory(@"c:\cloudflare", true, CancellationToken);
        result.Should().NotBeNullOrEmpty();
    }
}
