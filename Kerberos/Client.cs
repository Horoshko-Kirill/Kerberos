using Kerberos;
using Kerberos.Models;
using Microsoft.Extensions.Logging;

public class Client
{
    private readonly ILogger<Client> _logger;
    public string ClientId { get; set; }
    public byte[] Key { get; set; }

    private byte[] sessionKey;
    private byte[] tgt;
    private byte[] serviceSessionKey;
    private byte[] serviceTicket;

    public Client(string clientId, byte[] key, ILogger<Client> logger)
    {
        ClientId = clientId;
        Key = key;
        _logger = logger;
    }

    public void RequestTgt(AuthenticationServer asServer)
    {
        var (encryptedSessionKey, encryptedTgt) = asServer.Authenticate(ClientId);
        sessionKey = Convert.FromBase64String(CryptoHelper.Decrypt(encryptedSessionKey, Key));
        tgt = encryptedTgt;
        _logger.LogInformation("[CLIENT] TGT получен для {ClientId}", ClientId);
    }

    public void RequestServiceTicket(TicketGrantingServer tgs, string serviceId)
    {
        var authenticator = new Authenticator(ClientId);
        var encryptedAuthenticator = CryptoHelper.Encrypt(authenticator.Serialize(), sessionKey);

        var (encryptedServiceSessionKey, encryptedServiceTicket) = tgs.RequestServiceTicket(tgt, encryptedAuthenticator, ClientId, serviceId);
        serviceSessionKey = Convert.FromBase64String(CryptoHelper.Decrypt(encryptedServiceSessionKey, sessionKey));
        serviceTicket = encryptedServiceTicket;

        _logger.LogInformation("[CLIENT] Service ticket получен для {ClientId} -> {ServiceId}", ClientId, serviceId);
    }

    public void AccessService(ServiceServer service, string serviceId)
    {
        var authenticator = new Authenticator(ClientId);
        var encryptedAuthenticator = CryptoHelper.Encrypt(authenticator.Serialize(), serviceSessionKey);

        service.AccessService(serviceTicket, encryptedAuthenticator, ClientId, serviceId);
    }
}
