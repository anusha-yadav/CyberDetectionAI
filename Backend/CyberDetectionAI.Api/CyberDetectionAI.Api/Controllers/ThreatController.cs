using CyberDetectionAI.Application.DTOs;
using CyberDetectionAI.Application.Interfaces;
using CyberDetectionAI.Infrastructure.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace CyberDetectionAI.Api.Controllers
{
    [ApiController]
    [Route("api/threat")]
    public class ThreatController : ControllerBase
    {
        private readonly IThreatAnalysisService _service;
        private readonly ApplicationDbContext _context;

        public ThreatController(
            IThreatAnalysisService service, ApplicationDbContext context)
        {
            _service = service;
            _context = context;
        }

        [HttpPost("url")]
        public async Task<IActionResult>
            AnalyzeUrl(
                UrlScanRequest request)
        {
            return Ok(
                await _service
                    .AnalyzeUrlAsync(request.Url));
        }

        [HttpPost("email")]
        public async Task<IActionResult>
            AnalyzeEmail(
                EmailScanRequest request)
        {
            return Ok(
                await _service
                    .AnalyzeEmailAsync(
                        request.Body));
        }

        [HttpGet("history")]
        public async Task<IActionResult> GetHistory()
        {
            var history = await _context.Scans
                .Include(x => x.ThreatResult)
                .OrderByDescending(x => x.CreatedDate)
                .Select(x => new ScanHistoryDto
                {
                    ScanId = x.Id,
                    ScanType = x.ScanType,
                    Content = x.Content,
                    RiskScore = x.ThreatResult!.RiskScore,
                    Status = x.ThreatResult.Status,
                    CreatedDate = x.CreatedDate
                })
                .ToListAsync();

            return Ok(history);
        }

        [HttpGet("auditlogs")]
        public async Task<IActionResult> GetAuditLogs()
        {
            var logs = await _context.AuditLogs
                .OrderByDescending(x => x.CreatedOn)
                .ToListAsync();

            return Ok(logs);
        }
    }


}
