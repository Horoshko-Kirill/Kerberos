namespace Kerberos.Models
{
    public class Authenticator
    {
        public string ClientId { get; set; }
        public DateTime Timestamp { get; set; }

        public Authenticator(string clientId)
        {
            ClientId = clientId;
            Timestamp = DateTime.UtcNow;
        }
        public string Serialize()
        {
            return $"{ClientId}|{Timestamp.Ticks}";
        }
        public static Authenticator Deserialize(string data)
        {
            var parts = data.Split('|');
            return new Authenticator(parts[0])
            {
                Timestamp = new DateTime(long.Parse(parts[1]))
            };
        }
    }
}
