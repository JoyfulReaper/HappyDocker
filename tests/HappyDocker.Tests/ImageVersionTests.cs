namespace HappyDocker.Tests;

[TestClass]
public sealed class ImageVersionTests
{
    [TestMethod]
    [DataRow("1.2.3", false, "")]
    [DataRow("v1.2.3", true, "")]
    [DataRow("1.2.3-alpine", false, "-alpine")]
    [DataRow("v1.2.3-alpine", true, "-alpine")]
    [DataRow("v1.2.3-alpine3.22", true, "-alpine3.22")]
    public void ParsePreservesPrefixAndVariant(string tag, bool prefix, string variant)
    {
        ImageVersion? parsed = ImageVersion.Parse(tag);
        Assert.IsNotNull(parsed);
        Assert.AreEqual(1, parsed.Major);
        Assert.AreEqual(2, parsed.Minor);
        Assert.AreEqual(3, parsed.Patch);
        Assert.AreEqual(prefix, parsed.HasVPrefix);
        Assert.AreEqual(variant, parsed.Variant);
    }

    [TestMethod]
    [DataRow(null)]
    [DataRow("")]
    [DataRow("V1.2.3")]
    [DataRow("vv1.2.3")]
    [DataRow("v01.2.3")]
    [DataRow("v1.02.3")]
    [DataRow("v1.2.03")]
    [DataRow("1.2.03")]
    [DataRow("v1.2")]
    [DataRow("v1.2.3.4")]
    [DataRow("v1.2.3+build")]
    [DataRow(" v1.2.3")]
    [DataRow("v1.2.3\n")]
    [DataRow("v1.2.3-rc1")]
    [DataRow("v1.2.3-alpine-rc1")]
    [DataRow("v1.2.3-beta.1")]
    [DataRow("v1.2.3-dev")]
    [DataRow("v1.2.3-abcdef12")]
    [DataRow("v1.2.3-1")]
    [DataRow("latest")]
    [DataRow("vlatest")]
    [DataRow("v2147483648.2.3")]
    [DataRow("v1.2147483648.3")]
    [DataRow("v1.2.2147483648")]
    [DataRow("1.2.2147483648")]
    public void InvalidOrUnstableTagsRemainRejected(string? tag) => Assert.IsNull(ImageVersion.Parse(tag));

    [TestMethod]
    [DataRow("2147483647.2147483647.2147483647")]
    [DataRow("v2147483647.2147483647.2147483647")]
    public void NumericComponentsRetainTheirExistingUpperBound(string tag)
    {
        ImageVersion? parsed = ImageVersion.Parse(tag);
        Assert.IsNotNull(parsed);
        Assert.AreEqual(int.MaxValue, parsed.Major);
        Assert.AreEqual(int.MaxValue, parsed.Minor);
        Assert.AreEqual(int.MaxValue, parsed.Patch);
    }

    [TestMethod]
    [DataRow("1.2.3", "1.2.10")]
    [DataRow("v1.2.3", "v1.2.10")]
    [DataRow("1.2.3-alpine", "1.2.10-alpine")]
    [DataRow("v1.2.3-alpine", "v2.2.999-alpine")]
    [DataRow("v1.2.3-alpine3.22", "v1.2.10-alpine3.22")]
    public void HighestCandidateUsesNumericVersionsAndPreservesPrefixAndVariant(string current, string expected)
    {
        ImageVersion? parsed = ImageVersion.Parse(current);
        Assert.IsNotNull(parsed);
        Assert.AreEqual(expected, parsed.Candidates([
            "1.2.9", "1.2.10", "v1.2.9", "v1.2.10",
            "1.2.9-alpine", "1.2.10-alpine", "v1.2.9-alpine", "v1.2.10-alpine",
            "v1.2.9-alpine3.22", "v1.2.10-alpine3.22",
            "v1.2.999-Alpine", "v1.2.999-alpine3.23", "v1.3.999-alpine", "v2.2.999-alpine",
            "v1.2.999-alpine-rc1", "v1.2.2147483648-alpine", "latest", "dev"
        ]).FirstOrDefault());
    }

    [TestMethod]
    [DataRow("v1.2.3", "1.2.99")]
    [DataRow("1.2.3", "v1.2.99")]
    [DataRow("v1.2.3-alpine", "1.2.99-alpine")]
    [DataRow("1.2.3-alpine", "v1.2.99-alpine")]
    [DataRow("v1.2.3-alpine", "v1.2.99")]
    [DataRow("v1.2.3-alpine", "v1.2.99-Alpine")]
    [DataRow("v1.2.3-alpine", "v1.2.99-alpine3.22")]
    [DataRow("v1.2.3", "v1.2.3")]
    [DataRow("v1.2.3", "v1.2.2")]
    [DataRow("v1.2.3", "v1.2.99-rc1")]
    public void MismatchedOrNonNewerCandidatesAreExcluded(string current, string candidate)
    {
        ImageVersion? parsed = ImageVersion.Parse(current);
        Assert.IsNotNull(parsed);
        Assert.IsNull(parsed.Candidates([candidate]).FirstOrDefault());
    }

    [TestMethod]
    [DataRow("1.2.3", "1.2.4", VersionUpgrade.Patch)]
    [DataRow("1.2.3", "1.3.0", VersionUpgrade.Minor)]
    [DataRow("1.2.3", "2.0.0", VersionUpgrade.Major)]
    [DataRow("v2.26.0", "v2.27.0", VersionUpgrade.Minor)]
    [DataRow("2.14.8-alpine", "2.15.1-alpine", VersionUpgrade.Minor)]
    [DataRow("v1.9.9-alpine3.22", "v1.10.0-alpine3.22", VersionUpgrade.Minor)]
    public void ClassifiesAllStableUpgradeLevels(string current, string candidate, VersionUpgrade expected)
    {
        ImageVersion? version = ImageVersion.Parse(current);
        Assert.IsNotNull(version);
        Assert.AreEqual(expected, version.UpgradeTo(candidate));
    }

    [TestMethod]
    public void CandidateOrderIsNumericAcrossEveryComponent()
    {
        ImageVersion? version = ImageVersion.Parse("v1.2.3-alpine");
        Assert.IsNotNull(version);
        CollectionAssert.AreEqual(new[] { "v10.0.0-alpine", "v2.0.0-alpine", "v1.10.0-alpine", "v1.9.0-alpine", "v1.2.10-alpine", "v1.2.9-alpine" },
            version.Candidates(["v1.2.9-alpine", "v1.9.0-alpine", "v2.0.0-alpine", "v1.10.0-alpine", "v10.0.0-alpine",
                "v1.2.10-alpine", "v99.0.0-alpine-rc1", "99.0.0-alpine", "v99.0.0-Alpine", "latest"]));
    }
}
