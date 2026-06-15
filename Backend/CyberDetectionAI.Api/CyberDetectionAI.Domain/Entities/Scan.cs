using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CyberDetectionAI.Domain.Entities
{
    public class Scan
    {
        public Guid Id { get; set; }

        public string ScanType { get; set; } = string.Empty;

        public string Content { get; set; } = string.Empty;

        public DateTime CreatedDate { get; set; }

        public ThreatResult? ThreatResult { get; set; }
    }
}
