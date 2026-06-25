using System.Text.Json;
using PolyAuth.Mcp;
using Xunit;

namespace PolyAuth.Tests;

public sealed class McpToolHelpersTests
{
    [Theory]
    [InlineData(typeof(ArgumentException), "invalid_argument")]
    [InlineData(typeof(InvalidOperationException), "operation_failed")]
    [InlineData(typeof(UnauthorizedAccessException), "forbidden")]
    public void Maps_known_exceptions_to_error_codes(Type exceptionType, string expectedCode)
    {
        var exception = (Exception)Activator.CreateInstance(exceptionType, "boom")!;
        var mapped = McpToolHelpers.TryBuildUserFacingToolError(exception, out var result, out var error);

        Assert.True(mapped);
        Assert.True(result.IsError);
        Assert.Equal(expectedCode, error.ErrorCode);
    }

    [Fact]
    public void Maps_json_exception_to_invalid_argument()
    {
        var exception = new JsonException("bad json");
        Assert.True(McpToolHelpers.TryBuildUserFacingToolError(exception, out _, out var error));
        Assert.Equal("invalid_argument", error.ErrorCode);
    }

    [Fact]
    public void Unknown_exception_is_not_mapped()
    {
        Assert.False(McpToolHelpers.TryBuildUserFacingToolError(new Exception("???"), out _, out _));
    }

    [Fact]
    public void Unexpected_error_has_stable_code()
    {
        var result = McpToolHelpers.BuildUnexpectedToolError();
        Assert.True(result.IsError);
        var json = JsonSerializer.Serialize(result.StructuredContent);
        Assert.Contains("unexpected_error", json);
    }
}
