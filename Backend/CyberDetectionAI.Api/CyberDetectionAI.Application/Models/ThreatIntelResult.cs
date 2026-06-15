using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CyberDetectionAI.Application.Models
{
    public class ThreatIntelResult
    {
        public bool IsBlacklisted { get; set; }

        public int MaliciousReports { get; set; }

        public bool IsNewDomain { get; set; }

        public int DomainAgeInDays { get; set; }

        public bool HasValidSsl { get; set; }

        public double ReputationScore { get; set; }

        public List<string> Sources { get; set; } = [];
    }
}
