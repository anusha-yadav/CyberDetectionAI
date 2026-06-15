using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CyberDetectionAI.Domain.Entities
{
    public class AuditLog
    {
        public Guid Id { get; set; }

        public string Action { get; set; } = string.Empty;

        public string Details { get; set; } = string.Empty;

        public DateTime CreatedOn { get; set; }
    }
}
