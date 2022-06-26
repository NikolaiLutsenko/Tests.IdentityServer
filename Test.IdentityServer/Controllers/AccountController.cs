using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.IdentityModel.Tokens.Jwt;
using Test.IdentityServer.Dto;
using Test.IdentityServer.Services;

namespace Test.IdentityServer.Controllers;

[ApiController]
[Route("api/v1/[controller]")]
public class AccountController : Controller
{
    private readonly UserManager<IdentityUser> _userManager;
    private readonly IJwtGenerator _jwtGenerator;

    public AccountController(
        UserManager<IdentityUser> userManager,
        IJwtGenerator jwtGenerator)
    {
        this._userManager = userManager;
        this._jwtGenerator = jwtGenerator;
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterDto model)
    {
        var userExists = await _userManager.FindByNameAsync(model.UserName);
        if (userExists != null)
            return StatusCode(StatusCodes.Status400BadRequest, new { Message = "User already exists!" });

        IdentityUser user = new()
        {
            Email = model.Email,
            SecurityStamp = Guid.NewGuid().ToString(),
            UserName = model.UserName
        };
        var result = await _userManager.CreateAsync(user, model.Password);
        if (!result.Succeeded)
            return StatusCode(StatusCodes.Status400BadRequest, new { Status = "Error", Message = "User creation failed! Please check user details and try again." });

        var securityToken = await _jwtGenerator.Generate(user);
        return Ok(new
        {
            Token = new JwtSecurityTokenHandler().WriteToken(securityToken),
            ExpireAt = new DateTimeOffset(securityToken.ValidTo).ToUnixTimeSeconds()
        });
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginDto model)
    {
        var user = await _userManager.FindByNameAsync(model.UserName);
        if (user != null && await _userManager.CheckPasswordAsync(user, model.Password))
        {
            var securityToken = await _jwtGenerator.Generate(user);
            return Ok(new
            {
                Token = new JwtSecurityTokenHandler().WriteToken(securityToken),
                ExpireAt = new DateTimeOffset(securityToken.ValidTo).ToUnixTimeSeconds()
            });
        }
        return Unauthorized();
    }

    [Authorize(Policy = "policy1")]
    [HttpGet("test")]
    public IActionResult Test()
    {
        return Ok("secured");
    }
}
