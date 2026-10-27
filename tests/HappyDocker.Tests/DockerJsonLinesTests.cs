using System.Text.Json;

namespace HappyDocker.Tests;

[TestClass]
public sealed class DockerJsonLinesTests
{
    [TestMethod]
    public void Parse_MultipleRecords_ReturnsAllContainers()
    {
        const string output =
            """
            {"Id":"aaa","Name":"/first","ImageId":"sha256:111","ConfiguredImage":"nginx:1","Platform":"linux"}
            {"Id":"bbb","Name":"/second","ImageId":"sha256:222","ConfiguredImage":"redis:7","Platform":"linux"}
            """;

        List<DockerInspectRow> containers = DockerJsonLines.Parse<DockerInspectRow>(output);

        Assert.HasCount(2, containers);
        Assert.AreEqual("/first", containers[0].Name);
        Assert.AreEqual("nginx:1", containers[0].ConfiguredImage);
        Assert.AreEqual("/second", containers[1].Name);
        Assert.AreEqual("sha256:222", containers[1].ImageId);
    }

    [TestMethod]
    public void Parse_InvalidJson_ThrowsJsonException()
    {
        const string output = "{this is not valid JSON}";

        Assert.ThrowsExactly<JsonException>(
            () => DockerJsonLines.Parse<DockerInspectRow>(output));
    }

    [TestMethod]
    public void Parse_MissingRequiredField_ThrowsJsonException()
    {
        const string output =
            """{"Id":"aaa","Name":"/first","ImageId":"sha256:111","ConfiguredImage":"nginx:1"}""";

        Assert.ThrowsExactly<JsonException>(
            () => DockerJsonLines.Parse<DockerInspectRow>(output));
    }

    [TestMethod]
    public void Parse_ImageWithoutRepositoryDigests_Succeeds()
    {
        const string output =
            """
        {"Id":"sha256:abc","Os":"linux","Architecture":"amd64","Variant":null,"RepoDigests":null}
        """;

        List<DockerImageRow> images = DockerJsonLines.Parse<DockerImageRow>(output);

        Assert.HasCount(1, images);
        Assert.AreEqual("linux", images[0].Os);
        Assert.AreEqual("amd64", images[0].Architecture);
        Assert.IsNull(images[0].Variant);
        Assert.IsNull(images[0].RepoDigests);
    }
}