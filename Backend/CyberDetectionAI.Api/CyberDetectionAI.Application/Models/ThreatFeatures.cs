using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CyberDetectionAI.Application.Models
{
    public class ThreatFeatures
    {
        public string Domain { get; set; } = string.Empty;

        public int UrlLength { get; set; }

        public int HyphenCount { get; set; }

        public int DotCount { get; set; }

        public bool ContainsIpAddress { get; set; }

        public bool ContainsLoginKeyword { get; set; }

        public bool ContainsVerifyKeyword { get; set; }

        public bool ContainsBankKeyword { get; set; }

        public bool ContainsAtSymbol { get; set; }

        public bool UsesHttps { get; set; }

        public double EntropyScore { get; set; }
    }
}
