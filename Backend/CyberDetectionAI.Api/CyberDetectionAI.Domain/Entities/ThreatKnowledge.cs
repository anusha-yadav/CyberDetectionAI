using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CyberDetectionAI.Domain.Entities
{
    public class ThreatKnowledge
    {
        public Guid Id { get; set; }

        public string Content { get; set; } = string.Empty;

        public string ThreatType { get; set; } = string.Empty;

        public string Status { get; set; } = string.Empty;

        public int RiskScore { get; set; }

        public string Embedding { get; set; } = string.Empty;

        public DateTime CreatedOn { get; set; }
    }
}
