using Kerberos.Models;
using Microsoft.Extensions.Logging;

namespace Kerberos
{
    public class AuthenticationServer
    {
        private readonly ILogger<AuthenticationServer> _logger;
        private Dictionary<string, byte[]> users = new Dictionary<string, byte[]>(); 
        private byte[] tgsKey;

        public AuthenticationServer(byte[] tgsKey, ILogger<AuthenticationServer> logger)
        {
            this.tgsKey = tgsKey;
            _logger = logger;

            users["user1"] = CryptoHelper.GenerateRandomKey();
            users["user2"] = CryptoHelper.GenerateRandomKey();
        }

        public (byte[]? encryptedSessionKey, byte[]? encryptedTgt) Authenticate(string clientId)
        {
            if (!users.ContainsKey(clientId))
            {
                _logger.LogWarning("[AS] Неизвестный клиент: {ClientId}", clientId);
                return (null, null);
            }

            var sessionKey = CryptoHelper.GenerateRandomKey();
            var tgt = new Ticket(clientId, sessionKey, DateTime.UtcNow.AddMinutes(10));
            var encryptedTgt = CryptoHelper.Encrypt(tgt.Serialize(), tgsKey);
            var encryptedSessionKey = CryptoHelper.Encrypt(Convert.ToBase64String(sessionKey), users[clientId]);

            _logger.LogInformation("[AS] TGT создан для {ClientId}", clientId);
            return (encryptedSessionKey, encryptedTgt);
        }

        public byte[]? GetUserKey(string clientId) => users.ContainsKey(clientId) ? users[clientId] : null;
    }

}
