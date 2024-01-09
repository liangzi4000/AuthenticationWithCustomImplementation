using AuthenticationNAuthorization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication(HeaderAuthenticationHandler.SchemeName)
            .AddScheme<AuthenticationSchemeOptions, HeaderAuthenticationHandler>(HeaderAuthenticationHandler.SchemeName, null);
builder.Services.AddAuthorization();

// Authorize all APIs by default
builder.Services.AddAuthorization(o =>
{
    o.FallbackPolicy = new AuthorizationPolicyBuilder().AddAuthenticationSchemes(HeaderAuthenticationHandler.SchemeName)
    .RequireAuthenticatedUser()
    .Build();
});

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/hello", () =>
{
    return "hello world!";
})
.WithName("HelloWorldApi");

app.Run();