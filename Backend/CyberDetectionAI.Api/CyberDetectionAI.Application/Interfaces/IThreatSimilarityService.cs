using CyberDetectionAI.Application.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CyberDetectionAI.Application.Interfaces
{
    public interface IThreatSimilarityService
    {
        Task<List<ThreatSimilarityResult>>FindSimilarThreatsAsync(string content);
        Task AddThreatAsync(string content, string threatType, string status, int riskScore);

    }
}
