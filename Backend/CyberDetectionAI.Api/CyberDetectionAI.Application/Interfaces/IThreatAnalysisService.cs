using CyberDetectionAI.Application.DTOs;
using CyberDetectionAI.Application.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CyberDetectionAI.Application.Interfaces
{
    public interface IThreatAnalysisService
    {
        Task<ThreatAnalysisResponse> AnalyzeUrlAsync(string url);

        Task<ThreatAnalysisResponse> AnalyzeEmailAsync(string email);
        ThreatFeatures ExtractUrlFeatures(string url);
    }
}
