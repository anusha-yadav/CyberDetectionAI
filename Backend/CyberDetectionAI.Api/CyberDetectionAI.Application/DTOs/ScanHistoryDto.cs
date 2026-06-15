using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CyberDetectionAI.Application.DTOs
{
    public class ScanHistoryDto
    {
        public Guid ScanId { get; set; }

        public string ScanType { get; set; } = string.Empty;

        public string Content { get; set; } = string.Empty;

        public int RiskScore { get; set; }

        public string Status { get; set; } = string.Empty;

        public DateTime CreatedDate { get; set; }
    }
}
