using CyberDetectionAI.Application.Interfaces;
using CyberDetectionAI.Application.Models;
using CyberDetectionAI.Domain.Entities;
using CyberDetectionAI.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using HtmlAgilityPack;
using System.Xml;



namespace CyberDetectionAI.Infrastructure.Services
{
    public class ThreatSimilarityService : IThreatSimilarityService
    {
        private readonly ApplicationDbContext _context;

        private readonly IEmbeddingService _embeddingService;

        public ThreatSimilarityService(
            ApplicationDbContext context,
            IEmbeddingService embeddingService)
        {
            _context = context;
            _embeddingService = embeddingService;
        }

        public static string ExtractText(string html)
        {
            var doc = new HtmlDocument();
            doc.LoadHtml(html);

            return HtmlEntity.DeEntitize(doc.DocumentNode.InnerText);
        }

        public async Task<List<ThreatSimilarityResult>>FindSimilarThreatsAsync(string content)
        {
            var extractedText = ExtractText(content);
            var inputEmbedding = await _embeddingService.GenerateEmbeddingAsync(extractedText);
            var threats = await _context.ThreatKnowledgeBase.ToListAsync();
            var results = new List<ThreatSimilarityResult>();

            foreach (var threat in threats)
            {
                var storedEmbedding = JsonSerializer.Deserialize<float[]>(threat.Embedding);
                double similarity = _embeddingService.CosineSimilarity(inputEmbedding, storedEmbedding!);

                if (similarity > 0.75)
                {
                    results.Add(
                        new ThreatSimilarityResult
                        {
                            ThreatType = threat.ThreatType,
                            SimilarityScore = similarity,
                            Content = threat.Content
                        });
                }
            }

            return results
                .OrderByDescending(x => x.SimilarityScore)
                .ToList();
        }

        public async Task AddThreatAsync(string content, string threatType,
                                         string status, int riskScore)
        {
            var embedding = await _embeddingService.GenerateEmbeddingAsync(content);
            var text = ExtractText(content);

            var entity = new ThreatKnowledge
                            {
                                Id = Guid.NewGuid(),
                                Content = text,
                                ThreatType = threatType,
                                Status = status,
                                RiskScore = riskScore,
                                Embedding = JsonSerializer.Serialize(embedding),
                                CreatedOn = DateTime.UtcNow
                            };

            await _context.ThreatKnowledgeBase
                .AddAsync(entity);

            await _context.SaveChangesAsync();
        }
    }
}