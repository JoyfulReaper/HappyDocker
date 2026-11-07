using System.Text;

namespace HappyDocker.Tests;

[TestClass]
public sealed class GhcrCredentialsTests
{
    [TestMethod]
    public void AbsentConfiguration_IsAnonymous() => Assert.IsNull(GhcrCredentials.Load(null, null, null));

    [TestMethod]
    [DataRow(null, null, "ghp_fake", "USERNAME")]
    [DataRow("", null, "ghp_fake", "USERNAME")]
    [DataRow("fake:user", null, "ghp_fake", "USERNAME")]
    [DataRow("fixture-user", "unused-file", "ghp_fake", "Set only one")]
    [DataRow("fixture-user", "", "", "Set only one")]
    [DataRow("fixture-user", null, null, "TOKEN_FILE")]
    [DataRow("fixture-user", "", null, "nonempty file path")]
    [DataRow("fixture-user", null, "", "nonempty classic PAT")]
    [DataRow("fixture-user", null, "ghp_fake\n", "nonempty classic PAT")]
    [DataRow("fixture-user", null, "ghp_fake:invalid", "nonempty classic PAT")]
    public void InvalidConfiguration_HasSafeDiagnostic(string? user, string? file, string? token, string expected)
    {
        var error = Assert.ThrowsExactly<GhcrConfigurationException>(() => GhcrCredentials.Load(user, file, token));
        Assert.Contains(expected, error.Message);
        Assert.DoesNotContain("ghp_fake", error.ToString());
        Assert.DoesNotContain("unused-file", error.ToString());
        Assert.IsNull(error.InnerException);
    }

    [TestMethod]
    public void MissingAndUnreadableFiles_AreDistinguishedWithoutPrintingPath()
    {
        string missing = Path.Combine(Path.GetTempPath(), $"fixture-secret-{Guid.NewGuid()}");
        var absent = Assert.ThrowsExactly<GhcrConfigurationException>(() => GhcrCredentials.Load("fixture-user", missing, null));
        Assert.Contains("was not found", absent.Message);
        Assert.DoesNotContain(missing, absent.ToString());
        string lockedPath = Path.GetTempFileName();
        try
        {
            using var lockedFile = new FileStream(lockedPath, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
            var unreadable = Assert.ThrowsExactly<GhcrConfigurationException>(() => GhcrCredentials.Load("fixture-user", lockedPath, null));
            Assert.Contains("Unable to read", unreadable.Message);
            Assert.DoesNotContain(lockedPath, unreadable.ToString());
        }
        finally { File.Delete(lockedPath); }
    }

    [TestMethod]
    [DataRow("", "nonempty classic PAT")]
    [DataRow("\r\n", "nonempty classic PAT")]
    [DataRow(" ghp_fake\n", "nonempty classic PAT")]
    [DataRow("ghp_fake \n", "nonempty classic PAT")]
    [DataRow("ghp_fake\nmore", "nonempty classic PAT")]
    [DataRow("\uFEFFghp_fake\n", "nonempty classic PAT")]
    [DataRow("ghp_fake\r\n\n", null)]
    public void FileStripsOnlyTrailingNewlineCharacters(string contents, string? expectedError)
    {
        string path = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(path, Encoding.UTF8.GetBytes(contents));
            if (expectedError is null)
                Assert.IsNotNull(GhcrCredentials.Load("fixture-user", path, null));
            else
            {
                var error = Assert.ThrowsExactly<GhcrConfigurationException>(() => GhcrCredentials.Load("fixture-user", path, null));
                Assert.Contains(expectedError, error.Message);
                Assert.DoesNotContain("ghp_fake", error.ToString());
            }
        }
        finally { File.Delete(path); }
    }
}
