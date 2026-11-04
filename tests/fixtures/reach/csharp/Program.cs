using Newtonsoft.Json;

namespace Sample;

// Fixture for the reachability analyzer (CI contract test): one symbol is reached from Main, one is only used by dead code.
public static class Program
{
    public static void Main(string[] args)
    {
        object? model = Load(args.Length > 0 ? args[0] : "{}");
        Console.WriteLine(model);
    }

    private static object? Load(string text) => JsonConvert.DeserializeObject(text);

    private static void NeverCalled()
    {
        using var client = new System.Net.Http.HttpClient();
    }
}
