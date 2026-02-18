using Kerberos;
using Kerberos.Models;
using Microsoft.Extensions.Logging;

public class TicketGrantingServer
{
    private readonly ILogger<TicketGrantingServer> _logger;
    private byte[] tgsKey;
    private Dictionary<string, byte[]> serviceKeys = new Dictionary<string, byte[]>();

    public TicketGrantingServer(byte[] tgsKey, Dictionary<string, byte[]> serviceKeys, ILogger<TicketGrantingServer> logger)
    {
        this.tgsKey = tgsKey;
        _logger = logger;

        this.serviceKeys = serviceKeys;
    }

    public (byte[]? encryptedServiceSessionKey, byte[]? serviceTicket) RequestServiceTicket(byte[] encryptedTgt, byte[] encryptedAuthenticator, string clientId, string serviceId)
    {
        var tgtData = CryptoHelper.Decrypt(encryptedTgt, tgsKey);
        var tgt = Ticket.Deserialize(tgtData);

        if (tgt.ClientId != clientId || tgt.Expiration < DateTime.UtcNow)
        {
            _logger.LogWarning("[TGS] Неверный TGT для {ClientId}", clientId);
            return (null, null);
        }

        var authData = CryptoHelper.Decrypt(encryptedAuthenticator, tgt.SessionKey);
        var authenticator = Authenticator.Deserialize(authData);

        if ((DateTime.UtcNow - authenticator.Timestamp).TotalMinutes > 5)
        {
            _logger.LogWarning("[TGS] Authenticator истёк для {ClientId}", clientId);
            return (null, null);
        }

        var serviceSessionKey = CryptoHelper.GenerateRandomKey();
        var serviceTicketObj = new Ticket(clientId, serviceSessionKey, DateTime.UtcNow.AddMinutes(5));
        var encryptedServiceTicket = CryptoHelper.Encrypt(serviceTicketObj.Serialize(), serviceKeys[serviceId]);
        var encryptedServiceSessionKey = CryptoHelper.Encrypt(Convert.ToBase64String(serviceSessionKey), tgt.SessionKey);

        _logger.LogInformation("[TGS] Service ticket создан для {ClientId} -> {ServiceId}", clientId, serviceId);
        return (encryptedServiceSessionKey, encryptedServiceTicket);
    }
}
