using System.Text.Json;
using System.Text.Json.Nodes;
using HappyDocker.Web.Advisories;

namespace HappyDocker.Web.Tests;

[TestClass]
public sealed class AdvisoryParserTests
{
    [TestMethod]
    [DataRow("{\"vulnerabilities\":[]}")]
    public void CisaRejectsEmptyCatalogAndInvalidCount(string payload)
    {
        using var document = JsonDocument.Parse(payload);
        var now = new ManualClock().GetUtcNow();
        Assert.ThrowsExactly<JsonException>(() => AdvisoryParser.ParseCisa(document.RootElement, now.AddDays(-90), now));
    }

    [TestMethod]
    public void CisaRejectsMismatchedOrInvalidDeclaredCount()
    {
        foreach (JsonNode count in new JsonNode[] { JsonValue.Create(2)!, JsonValue.Create("1")! })
        {
            var root = new JsonObject { ["count"] = count,
                ["vulnerabilities"] = new JsonArray(AdvisoryFixture.CisaEntry()) };
            using var document = JsonDocument.Parse(root.ToJsonString());
            var now = new ManualClock().GetUtcNow();
            Assert.ThrowsExactly<JsonException>(() => AdvisoryParser.ParseCisa(document.RootElement, now.AddDays(-90), now));
        }
    }
    [TestMethod]
    public void CisaKeepsKnownExploitationSeparateFromSeverity()
    {
        var entry = AdvisoryFixture.CisaEntry();
        entry["severity"] = "critical"; // Not part of KEV's severity semantics.
        entry["cvss"] = 10;
        var item = AdvisoryFixture.ParseCisa(entry).Items.Single();
        Assert.IsNull(item.Severity);
        Assert.AreEqual("CVE-2026-1234", item.CveId);
        Assert.AreEqual("Example Vendor / Widget Server", item.Products.Single());
        Assert.AreEqual(new DateTimeOffset(2026, 11, 13, 0, 0, 0, TimeSpan.Zero), item.PublishedAt);
        var advisory = AdvisoryParser.Merge([item]).Single();
        Assert.IsTrue(advisory.KnownExploited);
        Assert.IsNull(advisory.Severity);
        Assert.AreEqual("www.cisa.gov", item.Link.Host);
    }

    [TestMethod]
    [DataRow("high")]
    [DataRow("critical")]
    public void GitHubUsesReportedSeverityAndCanonicalLink(string severity)
    {
        var entry = AdvisoryFixture.GitHubEntry(severity: severity);
        entry["cvss"] = new JsonObject { ["score"] = 1.0 };
        entry["html_url"] = "javascript:alert(document.cookie)";
        var item = AdvisoryFixture.ParseGitHub(entry).Items.Single();
        Assert.AreEqual(severity, item.Severity);
        Assert.AreEqual("npm: widget-package", item.Products.Single());
        Assert.AreEqual("https://github.com/advisories/GHSA-2345-6789-cfgh", item.Link.AbsoluteUri);
        Assert.IsFalse(AdvisoryParser.Merge([item]).Single().KnownExploited);
    }

    [TestMethod]
    public void DuplicateCvesMergeWhilePreservingSourceRecordsAndStrongestReportedSeverity()
    {
        var cisa = AdvisoryFixture.ParseCisa(AdvisoryFixture.CisaEntry(cve: "cve-2026-1234")).Items.Single();
        var high = AdvisoryFixture.ParseGitHub(AdvisoryFixture.GitHubEntry()).Items.Single();
        var critical = AdvisoryFixture.ParseGitHub(AdvisoryFixture.GitHubEntry(id: "GHSA-jmpq-rvwx-2345", severity: "critical")).Items.Single();
        var advisory = AdvisoryParser.Merge([cisa, high, critical, high]).Single();
        Assert.AreEqual("CVE-2026-1234", advisory.CveId);
        Assert.HasCount(3, advisory.Items);
        Assert.IsTrue(advisory.KnownExploited);
        Assert.AreEqual("critical", advisory.Severity);
        Assert.HasCount(2, advisory.Products);
    }

    [TestMethod]
    public void AdvisoriesWithoutCveKeepSeparateGhsaIdentitiesAndCanUseCveAliases()
    {
        var first = AdvisoryFixture.GitHubEntry(cve: null);
        var second = AdvisoryFixture.GitHubEntry(id: "GHSA-jmpq-rvwx-2345", cve: null);
        var items = AdvisoryFixture.ParseGitHub(first, second).Items;
        Assert.HasCount(2, AdvisoryParser.Merge(items));
        Assert.IsNull(items[0].CveId);
        var alias = AdvisoryFixture.GitHubEntry(cve: null);
        alias["identifiers"] = new JsonArray(new JsonObject { ["type"] = "CVE", ["value"] = "CVE-2026-1234" });
        Assert.AreEqual("CVE-2026-1234", AdvisoryFixture.ParseGitHub(alias).Items.Single().CveId);
    }

    [TestMethod]
    public void MixedMalformedFieldsAreSkippedAndDisplayTextIsBounded()
    {
        var good = AdvisoryFixture.GitHubEntry();
        good["description"] = new string('a', 2000);
        var missingTitle = AdvisoryFixture.GitHubEntry();
        missingTitle.Remove("summary");
        var badCve = AdvisoryFixture.GitHubEntry(cve: "not-a-cve");
        var badId = AdvisoryFixture.GitHubEntry(id: "GHSA-2345-6789-cfgh-evil");
        var badDate = AdvisoryFixture.GitHubEntry(date: "nonsense");
        var low = AdvisoryFixture.GitHubEntry(severity: "low");
        var missingSeverity = AdvisoryFixture.GitHubEntry();
        missingSeverity.Remove("severity");
        var numberCve = AdvisoryFixture.GitHubEntry();
        numberCve["cve_id"] = 1234;
        var parsed = AdvisoryFixture.ParseGitHub(good, missingTitle, badCve, badId, badDate, low, missingSeverity, numberCve);
        Assert.HasCount(1, parsed.Items);
        Assert.AreEqual(7, parsed.Skipped);
        Assert.AreEqual(600, parsed.Items.Single().Description.Length);
    }

    [TestMethod]
    [DataRow("cveID")]
    [DataRow("dateAdded")]
    [DataRow("vulnerabilityName")]
    [DataRow("product")]
    [DataRow("shortDescription")]
    public void InvalidCisaFieldsAreRejected(string field)
    {
        var entry = AdvisoryFixture.CisaEntry();
        entry[field] = field == "dateAdded" ? "2026-11-13-extra" : null;
        Assert.ThrowsExactly<JsonException>(() => AdvisoryFixture.ParseCisa(entry));
    }

    [TestMethod]
    public void WrongRootShapeIsRejectedAndWithdrawnOrOldAdvisoriesAreOmitted()
    {
        using var wrong = JsonDocument.Parse("{}");
        var now = new ManualClock().GetUtcNow();
        Assert.ThrowsExactly<JsonException>(() => AdvisoryParser.ParseCisa(wrong.RootElement, now.AddDays(-90), now));
        Assert.ThrowsExactly<JsonException>(() => AdvisoryParser.ParseGitHub(wrong.RootElement, now.AddDays(-90), now));
        var withdrawn = AdvisoryFixture.GitHubEntry();
        withdrawn["withdrawn_at"] = "2026-11-14T00:00:00Z";
        Assert.IsEmpty(AdvisoryFixture.ParseGitHub(withdrawn, AdvisoryFixture.GitHubEntry(date: "2020-01-01T00:00:00Z")).Items);
        Assert.IsEmpty(AdvisoryFixture.ParseCisa(AdvisoryFixture.CisaEntry(date: "2020-01-01")).Items);
    }

    [TestMethod]
    public void MissingOptionalDescriptionAndPackagesHaveHonestFallbacks()
    {
        var entry = AdvisoryFixture.GitHubEntry();
        entry["description"] = null;
        entry["vulnerabilities"] = new JsonArray(new JsonObject { ["package"] = null });
        var item = AdvisoryFixture.ParseGitHub(entry).Items.Single();
        Assert.AreEqual("No description provided by GitHub.", item.Description);
        Assert.IsEmpty(item.Products);
    }
}
