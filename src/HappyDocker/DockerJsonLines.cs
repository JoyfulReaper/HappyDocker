using System.Text.Json;

namespace HappyDocker;

public static class DockerJsonLines
{
    private static readonly JsonSerializerOptions Options = new()
    {
        RespectRequiredConstructorParameters = true,
        RespectNullableAnnotations = true
    };

    public static List<T> Parse<T>(string output) where T : class
    {
        var records = new List<T>();

        foreach (string line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            T record = JsonSerializer.Deserialize<T>(line, Options)
                ?? throw new JsonException("Docker returned a null JSON record.");

            records.Add(record);
        }

        return records;
    }
}