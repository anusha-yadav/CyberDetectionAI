using Azure.Core;
using Azure.Identity;
using Microsoft.Graph;
using Microsoft.Graph.Models;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.RegularExpressions;

static string ReplaceSuspiciousLinks(
    string html)
{
    var regex =
        new Regex(
            @"https?:\/\/[^\s""'>]+",
            RegexOptions.IgnoreCase);

    return regex.Replace(
        html,
        "[BLOCKED SUSPICIOUS LINK]");
}


var clientId = "422eec3e-d588-4932-8574-4814650821e6";

var scopes = new[]
{
"User.Read",
"Mail.ReadWrite"
};

var credential = new InteractiveBrowserCredential(
new InteractiveBrowserCredentialOptions
{
    ClientId = clientId,
    TenantId = "consumers",
    RedirectUri = new Uri("http://localhost")
});

var graphClient = new GraphServiceClient(
credential,
scopes);

var me = await graphClient.Me.GetAsync();

Console.WriteLine("Mailbox exists!");

var messages = await graphClient
.Me
.Messages
.GetAsync(requestConfig =>
{
    requestConfig.QueryParameters.Top = 5;

    requestConfig.QueryParameters.Orderby =
        new[] { "receivedDateTime desc" };

    requestConfig.QueryParameters.Filter =
        "isRead eq false";

    requestConfig.Headers.Add(
        "Prefer",
        "outlook.body-content-type=\"html\"");
});

var httpClient = new HttpClient();

foreach (var message in messages.Value!)
{
    // SKIP ALREADY PROCESSED EMAILS
    if (message.Subject != null &&
    message.Subject.Contains("[⚠ Suspicious]"))
    {
        continue;
    }
Console.WriteLine($"Subject: {message.Subject}");
    Console.WriteLine($"Received: {message.ReceivedDateTime}");

    var payload = new
    {
        Subject = message.Subject,
        Body = message.Body?.Content
    };

    var response =
        await httpClient.PostAsJsonAsync(
            "https://localhost:44391/api/threat/email",
            payload);

    var result =
        await response.Content.ReadAsStringAsync();

    Console.WriteLine(result);

    var analysis =
        JsonSerializer.Deserialize<
            ThreatAnalysisResponse>(
                result,
                new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                });

    if (analysis != null &&
        analysis.RiskScore > 70)
    {
        Console.WriteLine(
            "⚠ Suspicious Email Detected");

        // ORIGINAL HTML BODY
        var originalHtml =
            message.Body?.Content ?? "";

        // REPLACE ONLY SUSPICIOUS LINKS
        var updatedBody =
            ReplaceSuspiciousLinks(originalHtml);

        // WARNING BANNER
        var warningBanner =
"<div style='padding:12px;" +
 "background-color:#fff4cc;" +
 "border:2px solid #ff9800;" +
 "color:#663c00;" +
 "font-family:Segoe UI;" +
 "font-size:14px;" +
 "font-weight:bold;" +
 "margin-bottom:15px;'>" +

"⚠ CyberShield AI Warning<br/><br/>" +

"This email appears suspicious.<br/><br/>" +

"Risk Score: " + analysis.RiskScore + "<br/>" +

"Status: " + analysis.Status +

"</div>";


        // PREPEND WARNING
        updatedBody =
            warningBanner + updatedBody;

        // OVERWRITE SAME EMAIL
        await graphClient
            .Me
            .Messages[message.Id]
            .PatchAsync(
                new Message
                {
                    Subject =
                        $"[⚠ Suspicious] {message.Subject}",
                    Body = new ItemBody
                    {
                        ContentType =
                            BodyType.Html,

                        Content =
                            updatedBody
                    },

                    Categories =
                    [
                        "Suspicious"
                    ]
                });

        Console.WriteLine(
            "Email updated successfully.");
    }

}

public class ThreatAnalysisResponse
{
    public int RiskScore { get; set; }

    public string Status { get; set; }
        = string.Empty;

    public List<string> Reasons { get; set; }
        = [];

    public string? AiExplanation { get; set; }
}



