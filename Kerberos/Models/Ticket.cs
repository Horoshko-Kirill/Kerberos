namespace Kerberos.Models
{
    public class Ticket
    {
        public string ClientId { get; set; }
        public byte[] SessionKey { get; set; }
        public DateTime Expiration { get; set; }

        public Ticket(string clientId, byte[] sessionKey, DateTime expiration)
        {
            ClientId = clientId;
            SessionKey = sessionKey;
            Expiration = expiration;
        }

        public string Serialize()
        {
            return $"{ClientId}|{Convert.ToBase64String(SessionKey)}|{Expiration.Ticks}";
        }

        public static Ticket Deserialize(string data)
        {
            var parts = data.Split('|');
            return new Ticket(
                parts[0],
                Convert.FromBase64String(parts[1]),
                new DateTime(long.Parse(parts[2]))
            );
        }
    }
}
