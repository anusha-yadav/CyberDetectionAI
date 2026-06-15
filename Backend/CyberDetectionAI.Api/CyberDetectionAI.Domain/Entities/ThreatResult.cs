using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CyberDetectionAI.Domain.Entities
{
    public class ThreatResult
    {
        public Guid Id { get; set; }

        public Guid ScanId { get; set; }

        public int RiskScore { get; set; }

        public string Status { get; set; } = string.Empty;

        public string Explanation { get; set; } = string.Empty;

        public Scan Scan { get; set; } = null!;
    }
}
