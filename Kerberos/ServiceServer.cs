using Kerberos;
using Kerberos.Models;
using Microsoft.Extensions.Logging;

public class ServiceServer
{
    private readonly ILogger<ServiceServer> _logger;
    private Dictionary<string, byte[]> serviceKeys = new Dictionary<string, byte[]>();

    public ServiceServer(byte[] serviceKey, ILogger<ServiceServer> logger)
    {
        _logger = logger;
        serviceKeys["service1"] = serviceKey;
    }

    public bool AccessService(byte[] encryptedServiceTicket, byte[] encryptedAuthenticator, string clientId, string serviceId)
    {
        var serviceKey = serviceKeys[serviceId];
        var ticketData = CryptoHelper.Decrypt(encryptedServiceTicket, serviceKey);
        var ticket = Ticket.Deserialize(ticketData);

        if (ticket.ClientId != clientId || ticket.Expiration < DateTime.UtcNow)
        {
            _logger.LogWarning("[SERVICE] Неверный билет для {ClientId}", clientId);
            return false;
        }

        var authData = CryptoHelper.Decrypt(encryptedAuthenticator, ticket.SessionKey);
        var authenticator = Authenticator.Deserialize(authData);

        if ((DateTime.UtcNow - authenticator.Timestamp).TotalMinutes > 5)
        {
            _logger.LogWarning("[SERVICE] Authenticator истёк для {ClientId}", clientId);
            return false;
        }

        _logger.LogInformation("[SERVICE] Доступ разрешен для {ClientId} к {ServiceId}", clientId, serviceId);
        return true;
    }
}
