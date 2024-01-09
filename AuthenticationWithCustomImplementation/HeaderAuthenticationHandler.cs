using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using System.Text.Encodings.Web;

namespace AuthenticationNAuthorization
{
    public class HeaderAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
    {
        public const string SchemeName = "HeaderAuthentication";

        public HeaderAuthenticationHandler(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock) : base(options, logger, encoder, clock)
        {
        }

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if (Context.Request.Headers.TryGetValue("x-api-key", out var apiKey))
            {
                if (apiKey == "test-api-key")
                {
                    var claims = new[] {
                        new Claim(ClaimTypes.NameIdentifier, "xiao_long"),
                        new Claim(ClaimTypes.Name, "Xiao Long")
                    };
                    var identity = new ClaimsIdentity(claims, Scheme.Name); // Specify 2nd parameter authentionType to avoid 403 error when invoking the API.
                    var principal = new ClaimsPrincipal(identity);
                    var ticket = new AuthenticationTicket(principal, Scheme.Name);

                    return Task.FromResult(AuthenticateResult.Success(ticket));
                }
            }
            return Task.FromResult(AuthenticateResult.Fail("authentication failed"));
        }
    }
}
