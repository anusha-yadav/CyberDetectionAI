using CyberDetectionAI.Application.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CyberDetectionAI.Application.DTOs
{
    public class ThreatAnalysisResponse
    {
        public int RiskScore { get; set; }

        public string Status { get; set; } = string.Empty;

        public List<string> Reasons { get; set; } = [];

        public string? AiExplanation { get; set; }
        public ThreatFeatures? Features { get; set; }
        public ThreatIntelResult? ThreatIntel { get; set; }
    }
}
