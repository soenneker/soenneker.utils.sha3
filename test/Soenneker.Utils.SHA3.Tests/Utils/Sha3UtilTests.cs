using System.IO;
using System.Threading.Tasks;
using AwesomeAssertions;
using Soenneker.Tests.FixturedUnit;
using Soenneker.Utils.SHA3.Abstract;
using Soenneker.Utils.SHA3.Tests;
using Xunit;


namespace Soenneker.Utils.Sha3.Tests.Utils;

[Collection("Collection")]
public class Sha3UtilTests : FixturedUnitTest
{
    private readonly ISha3Util _util;

    public Sha3UtilTests(Fixture fixture, ITestOutputHelper output) : base(fixture, output)
    {
        _util = Resolve<ISha3Util>();
    }

    [Fact]
    public void HashString_should_hash_string()
    {
        string result = _util.HashString(Faker.Random.AlphaNumeric(20));
        result.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public void HashString_should_hash_string_consistently()
    {
        string? test = Faker.Random.AlphaNumeric(20);

        string result1 = _util.HashString(test);
        string result2 = _util.HashString(test);

        result1.Should().Be(result2);
    }

    [Fact]
    public async Task HashFile_should_hash()
    {
        string result = await _util.HashFile(Path.Combine("Resources", "testfile.txt"), true, CancellationToken);
        result.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task HashDirectory_should_hash()
    {
        string result = await _util.HashDirectory(@"c:\cloudflare", true, CancellationToken);
        result.Should().NotBeNullOrEmpty();
    }
}
