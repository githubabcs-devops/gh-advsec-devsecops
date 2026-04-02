// ⚠️ SECURITY WARNING: This file contains INTENTIONAL vulnerabilities
// for GitHub Advanced Security demonstration and training purposes.
// DO NOT use this code in production environments.
// DO NOT copy-paste without understanding security implications.
// These vulnerabilities are designed to trigger GHAS detection capabilities.

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Text.RegularExpressions;
using Microsoft.Data.SqlClient;
using Newtonsoft.Json;
using System.Text.Json;

namespace webapp01.Pages
{
    public class DevSecOps7492Model : PageModel
    {
        private readonly ILogger<DevSecOps7492Model> _logger;

        // SECURITY ISSUE: Hardcoded database credentials - for demo purposes only!
        private const string DB_CONNECTION = "Server=demo-server;Database=SecurityDemo;User Id=demouser;Password=DemoPass2026!;";
        
        // SECURITY ISSUE: Vulnerable regex pattern susceptible to ReDoS (Regular Expression Denial of Service)
        private static readonly Regex InsecureRegex = new Regex(@"^(([a-z])+.)+[A-Z]([a-z])+$", RegexOptions.None);
        
        // SECURITY ISSUE: API key hardcoded
        private const string API_KEY = "ghp_demo1234567890abcdefghijklmnopqrst";

        public DevSecOps7492Model(ILogger<DevSecOps7492Model> logger)
        {
            _logger = logger;
        }

        public List<string> LatestGHASNews { get; set; } = new();
        public int PageViews { get; set; }

        public void OnGet()
        {
            // SECURITY ISSUE: Log forging - unsanitized user input directly written to logs
            string userAgent = Request.Headers["User-Agent"].ToString();
            string remoteIp = Request.HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            string userName = Request.Query.ContainsKey("user") ? Request.Query["user"].ToString() ?? "anonymous" : "anonymous";
            
            // Log forging vulnerability - attacker can inject newlines and fake log entries
            _logger.LogInformation($"DevSecOps-7492 page accessed by: {userName} from IP: {remoteIp}");
            _logger.LogInformation($"User-Agent: {userAgent}");

            // Simulate page view counter
            PageViews = new Random().Next(1000, 5000);
            
            // Load latest GitHub Advanced Security news
            LoadLatestGHASNews();

            // SECURITY ISSUE: Vulnerable regex testing
            string testInput = Request.Query.ContainsKey("test") ? Request.Query["test"].ToString() ?? "" : "";
            if (!string.IsNullOrEmpty(testInput))
            {
                try
                {
                    // This regex is vulnerable to ReDoS attacks
                    var match = InsecureRegex.IsMatch(testInput);
                    // Log forging in conditional logic
                    _logger.LogInformation($"Regex test performed on input: {testInput}, result: {match}");
                }
                catch (Exception ex)
                {
                    // SECURITY ISSUE: Logging sensitive exception details
                    _logger.LogError($"Regex evaluation failed for user input: {testInput}. Exception details: {ex.ToString()}");
                }
            }

            // SECURITY ISSUE: SQL connection with hardcoded credentials
            try
            {
                using var sqlConnection = new SqlConnection(DB_CONNECTION);
                _logger.LogInformation("Establishing database connection for demo...");
                // Note: Not actually opening connection for demo safety
                // sqlConnection.Open();
            }
            catch (Exception ex)
            {
                _logger.LogError($"Database connection attempt failed: {ex.Message}");
            }

            // SECURITY ISSUE: Logging API key
            _logger.LogDebug($"Using API key for external service: {API_KEY.Substring(0, 10)}...");
        }

        private void LoadLatestGHASNews()
        {
            // Latest GitHub Advanced Security news for 2026
            LatestGHASNews = new List<string>
            {
                "GitHub Advanced Security introduces AI-powered vulnerability prioritization with Copilot integration",
                "CodeQL 2.25 released with support for 15+ programming languages and 50+ new security queries",
                "Secret scanning now detects over 250 token types with enhanced pattern matching algorithms",
                "New GHAS feature: Real-time security analysis in GitHub Copilot Chat for instant remediation advice",
                "Dependency review now includes license risk assessment and supply chain attack detection",
                "GitHub Security Advisories Database expands to 500,000+ CVEs with ML-enhanced matching",
                "Custom CodeQL packs can now be shared privately across GitHub Enterprise organizations",
                "Push protection blocks 95% of secret leaks before they reach repositories",
                "Security overview dashboard adds compliance mapping for SOC 2, ISO 27001, and NIST frameworks",
                "Code scanning autofix suggests secure code replacements with one-click remediation",
                "New API endpoints for security alert management and automated workflow integration",
                "GitHub Advanced Security for Azure DevOps reaches general availability"
            };

            // SECURITY ISSUE: Potential JSON deserialization vulnerability
            // Using older Newtonsoft.Json version (12.0.2) which has known vulnerabilities
            string jsonData = JsonConvert.SerializeObject(LatestGHASNews);
            var deserializedNews = JsonConvert.DeserializeObject<List<string>>(jsonData);
            
            // Log forging in deserialization logging
            _logger.LogInformation($"Loaded {LatestGHASNews.Count} GHAS news items. First item: {LatestGHASNews.FirstOrDefault() ?? "none"}");
            
            // SECURITY ISSUE: Mixing JSON libraries (both System.Text.Json and Newtonsoft.Json)
            var jsonOptions = new JsonSerializerOptions { WriteIndented = true };
            string systemTextJson = System.Text.Json.JsonSerializer.Serialize(LatestGHASNews, jsonOptions);
            _logger.LogDebug($"Serialized news data length: {systemTextJson.Length} characters");
        }

        public IActionResult OnPostTestPattern(string pattern)
        {
            if (string.IsNullOrEmpty(pattern))
            {
                TempData["Error"] = "Pattern cannot be empty";
                return Page();
            }

            // SECURITY ISSUE: Log forging in POST handler - user input directly in logs
            _logger.LogInformation($"User submitted pattern for testing: {pattern}");

            try
            {
                // SECURITY ISSUE: ReDoS vulnerable regex with user-supplied input
                var startTime = DateTime.Now;
                bool isMatch = InsecureRegex.IsMatch(pattern);
                var duration = (DateTime.Now - startTime).TotalMilliseconds;

                // Log forging with computation results
                _logger.LogInformation($"Pattern evaluation completed: {pattern} | Match: {isMatch} | Duration: {duration}ms");
                
                TempData["Message"] = $"Pattern '{pattern}' evaluation: {(isMatch ? "Match found" : "No match")} (took {duration}ms)";
            }
            catch (Exception ex)
            {
                // SECURITY ISSUE: Logging full exception with potentially sensitive information
                _logger.LogError($"Pattern test failed for input: {pattern} | Exception: {ex.ToString()}");
                TempData["Error"] = "Pattern evaluation encountered an error";
            }

            return Page();
        }
    }
}
