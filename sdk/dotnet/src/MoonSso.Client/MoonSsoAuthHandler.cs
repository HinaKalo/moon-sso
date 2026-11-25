using System.Net;
using System.Net.Http.Headers;

namespace MoonSso;

/// <summary>
/// <see cref="DelegatingHandler"/> that authenticates requests with the user's access token:
/// <list type="bullet">
/// <item>gets a valid token before every request (proactive refresh after 75 % of the lifetime);</item>
/// <item>on <c>401</c>, forces one refresh and replays the request once; a second 401 is returned to the caller;</item>
/// <item>the session is only ended when the refresh itself fails with <c>invalid_grant</c>.</item>
/// </list>
/// Request content is buffered before the first attempt so it can be replayed.
/// </summary>
public sealed class MoonSsoAuthHandler : DelegatingHandler
{
    private readonly TokenManager _tokens;

    public MoonSsoAuthHandler(TokenManager tokens)
    {
        _tokens = tokens ?? throw new ArgumentNullException(nameof(tokens));
    }

    public MoonSsoAuthHandler(MoonSsoClient client)
        : this((client ?? throw new ArgumentNullException(nameof(client))).Tokens)
    {
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var token = await _tokens.GetAccessTokenAsync(cancellationToken).ConfigureAwait(false);
        if (request.Content is not null)
        {
            await request.Content.LoadIntoBufferAsync().ConfigureAwait(false);
        }
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        var response = await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
        if (response.StatusCode != HttpStatusCode.Unauthorized)
        {
            return response;
        }

        TokenSet refreshed;
        try
        {
            refreshed = await _tokens.RefreshAfterRejectionAsync(token, cancellationToken).ConfigureAwait(false);
        }
        catch (MoonSsoException)
        {
            // Session expired (event already raised) or refresh unavailable: hand the original 401 to the caller.
            return response;
        }
        response.Dispose();
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", refreshed.AccessToken);
        return await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
    }
}
