using System.Text.Json;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;

if (args.Length is < 3 or > 4) throw new ArgumentException("usage: Client WORKDIR PORT MARKER [modern]");
string workdir = args[0];
int port = int.Parse(args[1]);
string marker = args[2];
bool modern = args.Length == 4 && args[3] == "modern";

var transport = new HttpClientTransport(new HttpClientTransportOptions
{
    Endpoint = new Uri($"http://127.0.0.1:{port}/mcp"),
    TransportMode = HttpTransportMode.StreamableHttp,
    Name = "mcptrace-dotnet-validation",
    AdditionalHeaders = new Dictionary<string, string> {
        ["X-MCPTrace-Case"] = modern ? "modern" : "legacy"
    },
});
await using var client = await McpClient.CreateAsync(transport,
    new McpClientOptions { ProtocolVersion = modern ? "2026-07-28" : "2025-11-25" });
var tools = await client.ListToolsAsync();
if (!tools.Any(tool => tool.Name == "echo_marker")) throw new Exception("missing tool");
for (int i = 0; i < 4; i++)
{
    string expected = $"{marker}-{i}";
    var result = await client.CallToolAsync(
        "echo_marker",
        new Dictionary<string, object?> { ["marker"] = expected }
    );
    if (result.IsError == true || !result.Content.OfType<TextContentBlock>().Any(item => item.Text == expected))
        throw new Exception("tool mismatch");
}
File.WriteAllText(Path.Combine(workdir, "client-ready.json"),
    JsonSerializer.Serialize(new { pid = Environment.ProcessId, marker }));
while (!File.Exists(Path.Combine(workdir, "client-stop")))
    await Task.Delay(100);
