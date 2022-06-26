using System.Runtime.Serialization;
using System.Text.Json.Serialization;

namespace Test.IdentityServer.Dto;

public class RegisterDto
{
    [JsonPropertyName("user_name")]
    public string UserName { get; set; }

    [JsonPropertyName("email")]
    public string Email { get; set; }

    [JsonPropertyName("password")]
    public string Password { get; set; }
}
