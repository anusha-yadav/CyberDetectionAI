using CyberDetectionAI.Application.Interfaces;
using CyberDetectionAI.Application.Models;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace CyberDetectionAI.Infrastructure.Services
{
    public class ThreatIntelligenceService : IThreatIntelligenceService
    {
        private readonly HttpClient _httpClient;

        private readonly IConfiguration _configuration;

        public ThreatIntelligenceService(
            HttpClient httpClient,
            IConfiguration configuration)
        {
            _httpClient = httpClient;
            _configuration = configuration;
        }

        public async Task<ThreatIntelResult>AnalyzeDomainAsync(string domain)
        {
            var result = new ThreatIntelResult();

            var apiKey = _configuration["VirusTotal:ApiKey"];

            var urlId =
                Convert.ToBase64String(
                    System.Text.Encoding.UTF8.GetBytes(domain))
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');

            _httpClient.DefaultRequestHeaders.Clear();

            _httpClient.DefaultRequestHeaders.Add(
                "x-apikey",
                apiKey);

            var response =
                await _httpClient.GetAsync(
                    $"https://www.virustotal.com/api/v3/urls/{urlId}");

            if (!response.IsSuccessStatusCode)
            {
                return result;
            }

            JsonElement data =
                await response.Content.ReadFromJsonAsync<JsonElement>();

            var attributes =
                data
                    .GetProperty("data")
                    .GetProperty("attributes");

            var stats =
                attributes
                    .GetProperty("last_analysis_stats");

            int malicious =
                stats
                    .GetProperty("malicious")
                    .GetInt32();

            int suspicious =
                stats
                    .GetProperty("suspicious")
                    .GetInt32();

            int reputation = 0;

            if (attributes.TryGetProperty("reputation", out JsonElement reputationElement))
            {
                reputation = reputationElement.GetInt32();
            }

            result.MaliciousReports =
                malicious + suspicious;

            result.IsBlacklisted =
                malicious > 0;

            result.ReputationScore =
                reputation;

            result.Sources.Add("VirusTotal");

            return result;
        }


    }
 }
