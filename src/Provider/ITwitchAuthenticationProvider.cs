namespace KatanaContrib.Security.Twitch
{
    using System.Threading.Tasks;

    public interface ITwitchAuthenticationProvider
    {
        Task Authenticated(TwitchAuthenticatedContext context);
        Task ReturnEndpoint(TwitchReturnEndpointContext context);
    }
}
