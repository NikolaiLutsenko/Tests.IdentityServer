using System.Text.Json.Serialization;

namespace Test.IdentityServer.Dto;

public class LoginDto
{
    [JsonPropertyName("user_name")]
    public string UserName { get; set; }

    [JsonPropertyName("password")]
    public string Password { get; set; }
}
