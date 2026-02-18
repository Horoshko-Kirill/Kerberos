using Kerberos;
using Microsoft.Extensions.Logging;

class Program
{
    static void Main()
    {
        using var loggerFactory = LoggerFactory.Create(builder =>
        {
            builder.AddConsole()
                   .SetMinimumLevel(LogLevel.Information);
        });

        ILogger logger = loggerFactory.CreateLogger<Program>();
        logger.LogInformation("=== Запуск Kerberos Simulation ===");

        var tgsKey = CryptoHelper.GenerateRandomKey();
        var service1Key = CryptoHelper.GenerateRandomKey();

        var asServer = new AuthenticationServer(tgsKey, loggerFactory.CreateLogger<AuthenticationServer>());

        var service = new ServiceServer(service1Key, loggerFactory.CreateLogger<ServiceServer>());
        var tgsServer = new TicketGrantingServer(tgsKey, serviceKeys: new Dictionary<string, byte[]> { ["service1"] = service1Key }, loggerFactory.CreateLogger<TicketGrantingServer>());

        var clientKey = asServer.GetUserKey("user1");
        var client = new Client("user1", clientKey, loggerFactory.CreateLogger<Client>());

        client.RequestTgt(asServer);
        client.RequestServiceTicket(tgsServer, "service1");
        client.AccessService(service, "service1");

        logger.LogInformation("=== Завершение работы ===");
        Console.ReadLine();
    }
}
