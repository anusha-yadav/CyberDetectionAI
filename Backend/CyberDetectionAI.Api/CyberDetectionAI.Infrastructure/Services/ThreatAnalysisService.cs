using CyberDetectionAI.Application.DTOs;
using CyberDetectionAI.Application.Interfaces;
using CyberDetectionAI.Application.Models;
using CyberDetectionAI.Domain.Entities;
using CyberDetectionAI.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Whois.NET;

namespace CyberDetectionAI.Infrastructure.Services
{
    public class ThreatAnalysisService : IThreatAnalysisService
    {
        private readonly ApplicationDbContext _context;
        private readonly IThreatIntelligenceService _threatIntelService;
        private readonly IThreatSimilarityService _threatSimilarityService;
        private readonly HttpClient _httpClient;

        public ThreatAnalysisService(ApplicationDbContext context, 
                                     IThreatIntelligenceService threatIntelService,
                                     IThreatSimilarityService threatSimilarityService,
                                     HttpClient httpClient)
        {
            _context = context;
            _threatIntelService = threatIntelService;
            _threatSimilarityService = threatSimilarityService;
            _httpClient = httpClient;
        }


        public async Task<int> AnalyzeDomainAsync(string domain)
        {
            int risk = 0;
            var response = await WhoisClient.QueryAsync(domain);
            if (response == null)
            {
                return risk;
            }
            var raw =
                response.Raw ?? "";
            var match =
                Regex.Match(
                    raw,
                    @"Creation Date:\s*(.+)");

            if (raw.Contains("No match for domain",StringComparison.OrdinalIgnoreCase))
            {
                risk += 50;
            }

            if (match.Success)
            {
                var createdText =
                    match.Groups[1].Value.Trim();

                if (DateTime.TryParse(
                    createdText,
                    out var createdDate))
                {
                    var age =
                        DateTime.UtcNow -
                        createdDate;

                    if (age.TotalDays < 30)
                    {
                        risk += 40;
                    }
                    else if (age.TotalDays < 90)
                    {
                        risk += 25;
                    }
                }
            }
            return risk;
        }

        public async Task<ThreatAnalysisResponse> AnalyzeUrlAsync(string url)
        {
            var reasons = new List<string>();
            int score = 0;
            var features = ExtractUrlFeatures(url);
            score += await AnalyzeDomainAsync(features.Domain);
            var intel = await _threatIntelService.AnalyzeDomainAsync(features.Domain);
            if (features.ContainsLoginKeyword)
            {
                score += 20;
                reasons.Add("Contains login keyword");
            }

            if (features.ContainsVerifyKeyword)
            {
                score += 20;
                reasons.Add("Contains verify keyword");
            }

            if (features.ContainsBankKeyword)
            {
                score += 15;
                reasons.Add("Contains banking keyword");
            }

            if (features.ContainsIpAddress)
            {
                score += 25;
                reasons.Add("Contains IP address instead of domain");
            }

            if (features.ContainsAtSymbol)
            {
                score += 20;
                reasons.Add("Contains suspicious @ symbol");
            }

            if (features.HyphenCount > 2)
            {
                score += 15;
                reasons.Add("Too many hyphens");
            }

            if (features.DotCount > 3)
            {
                score += 15;
                reasons.Add("Too many dots/subdomains");
            }

            if (features.UrlLength > 80)
            {
                score += 10;
                reasons.Add("Very long URL");
            }

            if (!features.UsesHttps)
            {
                score += 20;
                reasons.Add("Does not use HTTPS");
            }

            if (features.EntropyScore > 4.0)
            {
                score += 20;
                reasons.Add("High randomness detected");
            }

            if (intel.IsBlacklisted)
            {
                score += 50;

                reasons.Add(
                    "Domain flagged by threat intelligence");
            }

            if (intel.MaliciousReports > 5)
            {
                score += 25;

                reasons.Add(
                    "Multiple malicious reports detected");
            }

            var status =
                    score >= 70 ? "Dangerous" :
                    score >= 30 ? "Suspicious" :
                    "Safe";

            var scan = new Scan
            {
                Id = Guid.NewGuid(),
                ScanType = "URL",
                Content = url,
                CreatedDate = DateTime.UtcNow
            };

            var threatResult = new ThreatResult
            {
                Id = Guid.NewGuid(),
                ScanId = scan.Id,
                RiskScore = score,
                Status = status,
                Explanation = string.Join(", ", reasons)
            };

            var auditLog = new AuditLog
            {
                Id = Guid.NewGuid(),
                Action = "URL_SCAN",
                Details = $"URL analyzed with score {score}",
                CreatedOn = DateTime.UtcNow
            };

            await _context.Scans.AddAsync(scan);
            await _context.ThreatResults.AddAsync(threatResult);
            await _context.AuditLogs.AddAsync(auditLog);

            await _context.SaveChangesAsync();

            return new ThreatAnalysisResponse
            {
                RiskScore = score,
                Status = status,
                Reasons = reasons,
                Features = features,
                ThreatIntel = intel
            };
        }

        public async Task<ThreatAnalysisResponse>AnalyzeEmailAsync(string email)
        {
            var urls = ExtractUrls(email);
            var reasons = new List<string>();
            int score = 0;
            var similarThreats = await _threatSimilarityService.FindSimilarThreatsAsync(email);
            foreach (var url in urls)
            {
                var urlResult = await AnalyzeUrlAsync(url);
                score += urlResult.RiskScore;
                reasons.AddRange(urlResult.Reasons);
            }

            if (email.Contains("urgent",
                StringComparison.OrdinalIgnoreCase))
            {
                score += 20;
                reasons.Add("Uses urgency language");
            }

            if (email.Contains("click here",
                StringComparison.OrdinalIgnoreCase))
            {
                score += 20;
                reasons.Add("Contains suspicious action");
            }

            var status =
                score > 60 ? "Dangerous" :
                score > 30 ? "Suspicious" :
                "Safe";

            var scan = new Scan
            {
                Id = Guid.NewGuid(),
                ScanType = "EMAIL",
                Content = email,
                CreatedDate = DateTime.UtcNow
            };

            var threatResult = new ThreatResult
            {
                Id = Guid.NewGuid(),
                ScanId = scan.Id,
                RiskScore = score,
                Status = status,
                Explanation = string.Join(", ", reasons)
            };

            var auditLog = new AuditLog
            {
                Id = Guid.NewGuid(),
                Action = "EMAIL_SCAN",
                Details = $"Email analyzed with score {score}",
                CreatedOn = DateTime.UtcNow
            };

            if (similarThreats.Any())
            {
                var highestSimilarity =
                    similarThreats.Max(x =>
                        x.SimilarityScore);

                if (highestSimilarity >= 0.90)
                {
                    score += 40;

                    reasons.Add(
                        "Highly similar to known threat");
                }
                else if (highestSimilarity >= 0.75)
                {
                    score += 25;

                    reasons.Add(
                        "Similar to suspicious communication");
                }
            }

            await _context.Scans.AddAsync(scan);
            await _context.ThreatResults.AddAsync(threatResult);
            await _context.AuditLogs.AddAsync(auditLog);
            await _threatSimilarityService.AddThreatAsync(email,"Communication Threat",status,score);

            await _context.SaveChangesAsync();
            var aiExplanation = await GenerateExplanationAsync(score, reasons, email);

            return new ThreatAnalysisResponse
            {
                RiskScore = score,
                Status = status,
                Reasons = reasons,
                AiExplanation = aiExplanation
            };
        }

        public ThreatFeatures ExtractUrlFeatures(string url)
        {
            var uri = new Uri(url);

            var features = new ThreatFeatures
            {
                Domain = uri.Host,

                UrlLength = url.Length,

                HyphenCount =
                    url.Count(x => x == '-'),

                DotCount =
                    url.Count(x => x == '.'),

                ContainsIpAddress =
                    Regex.IsMatch(url,
                        @"\b\d{1,3}(\.\d{1,3}){3}\b"),

                ContainsLoginKeyword =
                    url.Contains("login",
                        StringComparison.OrdinalIgnoreCase),

                ContainsVerifyKeyword =
                    url.Contains("verify",
                        StringComparison.OrdinalIgnoreCase),

                ContainsBankKeyword =
                    url.Contains("bank",
                        StringComparison.OrdinalIgnoreCase),

                ContainsAtSymbol =
                    url.Contains("@"),

                UsesHttps =
                    url.StartsWith("https",
                        StringComparison.OrdinalIgnoreCase),

                EntropyScore =
                    CalculateEntropy(url)
            };

            return features;
        }



        public async Task<string> GenerateExplanationAsync(
    int riskScore,
    List<string> reasons,
    string emailContent)
        {
            try
            {
                // Reduce prompt size for faster inference
                var trimmedEmail =
                    string.IsNullOrWhiteSpace(emailContent)
                        ? string.Empty
                        : emailContent.Length > 800
                            ? emailContent[..800]
                            : emailContent;

                var prompt = $"""
        You are a cybersecurity assistant.

        Risk Score: {riskScore}

        Reasons:
        {string.Join(", ", reasons)}

        Email:
        {trimmedEmail}

        Respond in EXACTLY 1 short sentence.
        Maximum 25 words.
        Mention:
        - why suspicious
        - possible risk
        - simple caution
        """;

                var request = new
                {
                    // Faster model
                    model = "phi3",

                    prompt,

                    stream = false,

                    // Keep model loaded in memory
                    keep_alive = "30m",

                    options = new
                    {
                        // Smaller output = faster response
                        num_predict = 40,

                        // More deterministic
                        temperature = 0.1,

                        top_p = 0.9
                    }
                };

                var response = await _httpClient.PostAsJsonAsync(
                    "http://localhost:11434/api/generate",
                    request);

                response.EnsureSuccessStatusCode();

                JsonElement result =
                    await response.Content.ReadFromJsonAsync<JsonElement>();

                var aiResponse =
                    result.GetProperty("response").GetString();

                return string.IsNullOrWhiteSpace(aiResponse)
                    ? "Suspicious email detected; avoid clicking links or sharing personal information."
                    : aiResponse.Trim();
            }
            catch
            {
                return "Suspicious email detected; verify the sender before opening links or attachments.";
            }
        }


        private double CalculateEntropy(string text)
        {
            var map = new Dictionary<char, int>();

            foreach (char c in text)
            {
                if (!map.ContainsKey(c))
                {
                    map[c] = 0;
                }

                map[c]++;
            }

            double entropy = 0;

            foreach (var item in map)
            {
                double frequency =
                    (double)item.Value / text.Length;

                entropy -=
                    frequency * Math.Log2(frequency);
            }

            return entropy;
        }

        public List<string> ExtractUrls(string content)
        {
            var matches = Regex.Matches(
            content,
            @"https?://[^\s""'<>]+");

return matches
    .Select(x => CleanUrl(x.Value))
    .Where(x => !string.IsNullOrWhiteSpace(x))
    .Distinct()
    .ToList();

}

        private string CleanUrl(string url)
        {
            if (string.IsNullOrWhiteSpace(url))
            {
                return string.Empty;
            }


// REMOVE COMMON TRAILING CHARS
url = url.Trim(
    '.', ',', ';', ':',
    ')', ']', '>', '"', '\'');

            // REMOVE EMOJIS / NON ASCII
            url = Regex.Replace(
                url,
                @"[^\u0000-\u007F]+",
                "");

            return url.Trim();


}

    }
}
