using CyberDetectionAI.Application.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CyberDetectionAI.Application.Interfaces
{
    public interface IThreatIntelligenceService
    {
        Task<ThreatIntelResult> AnalyzeDomainAsync(string domain);
    }
}
