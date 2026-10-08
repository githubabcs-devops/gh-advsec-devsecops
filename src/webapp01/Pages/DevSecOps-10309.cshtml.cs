using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Text.RegularExpressions;
using Microsoft.Data.SqlClient;
using Newtonsoft.Json;
using System.Text.Json;

namespace webapp01.Pages
{
    public class DevSecOps_10309Model : PageModel
    {
        private readonly ILogger<DevSecOps_10309Model> _logger;

        // VULNERABILITY: Hardcoded credentials - INSECURE
        // This should be detected by GHAS secret scanning
        private const string CONNECTION_STRING = "Server=prod-sql-server.database.windows.net;Database=ProductionDB;User Id=sa;Password=P@ssw0rd123!Admin;";
        private const string API_KEY = "ghp_1234567890abcdefghijklmnopqrstuvwxyz12";
        
        // VULNERABILITY: Weak regex pattern - susceptible to ReDoS (Regular Expression Denial of Service)
        // Pattern with nested quantifiers can cause exponential backtracking
        private static readonly Regex VulnerableRegex = new Regex(@"^(a+)+$", RegexOptions.Compiled);
        private static readonly Regex EmailRegex = new Regex(@"^([a-zA-Z0-9_\-\.]+)@([a-zA-Z0-9_\-\.]+)\.([a-zA-Z]{2,5})$", RegexOptions.Compiled);

        public DevSecOps_10309Model(ILogger<DevSecOps_10309Model> logger)
        {
            _logger = logger;
            _logger.LogInformation("DevSecOps_10309Model initialized");
        }

        public List<string> LatestNews { get; set; } = new();

        public void OnGet()
        {
            // VULNERABILITY: Log forging - user input directly in logs without sanitization
            string userInput = Request.Query.ContainsKey("user") ? Request.Query["user"].ToString() ?? "anonymous" : "anonymous";
            _logger.LogInformation($"User accessed DevSecOps-10309 page: {userInput}");

            string ipAddress = Request.HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            // VULNERABILITY: Logging sensitive information
            _logger.LogInformation($"Access from IP: {ipAddress}, User-Agent: {Request.Headers["User-Agent"]}");

            // Load latest GHAS news
            LoadLatestGHASNews();

            // Demonstrate ReDoS vulnerability
            string testPattern = Request.Query.ContainsKey("pattern") ? Request.Query["pattern"].ToString() ?? "aaa" : "aaa";
            try
            {
                // VULNERABILITY: No timeout on regex - can cause ReDoS
                bool isMatch = VulnerableRegex.IsMatch(testPattern);
                // VULNERABILITY: Log forging with user input
                _logger.LogInformation($"Regex pattern match result: {isMatch} for input: {testPattern}");
            }
            catch (Exception ex)
            {
                // VULNERABILITY: Logging full exception details including stack trace
                _logger.LogError($"Regex evaluation failed for pattern: {testPattern}. Error: {ex.ToString()}");
            }

            // VULNERABILITY: Using hardcoded connection string
            try
            {
                using var connection = new SqlConnection(CONNECTION_STRING);
                _logger.LogInformation("Database connection string configured with hardcoded credentials");
                // Don't actually open connection for demo purposes
            }
            catch (Exception ex)
            {
                _logger.LogError($"Database connection failed: {ex.Message}");
            }
        }

        private void LoadLatestGHASNews()
        {
            _logger.LogInformation("Loading latest GitHub Advanced Security news...");

            LatestNews = new List<string>
            {
                "GitHub Copilot for Security now includes advanced vulnerability remediation with AI-powered fix suggestions",
                "CodeQL analysis expanded to support 25+ programming languages including Rust, Go, and Kotlin",
                "Secret scanning now detects 200+ credential patterns with enhanced push protection",
                "New GHAS API endpoints for programmatic security management and automation",
                "Advanced Security dashboard now includes real-time vulnerability trending and risk scoring",
                "Dependency review includes SBOM generation and supply chain security attestation",
                "GitHub Advanced Security for Azure DevOps now generally available",
                "Custom CodeQL queries marketplace with community-contributed security checks",
                "Machine learning-powered false positive reduction in code scanning alerts",
                "Integration with SIEM tools for enterprise security operations centers",
                "Automated security policy enforcement with required checks and branch protection",
                "Container security scanning integrated with GitHub Actions workflows"
            };

            // VULNERABILITY: Insecure deserialization with Newtonsoft.Json
            // Using TypeNameHandling.Auto can lead to deserialization vulnerabilities
            string jsonData = JsonConvert.SerializeObject(LatestNews, new JsonSerializerSettings
            {
                TypeNameHandling = TypeNameHandling.Auto // VULNERABILITY: Insecure setting
            });
            
            var deserializedData = JsonConvert.DeserializeObject<List<string>>(jsonData, new JsonSerializerSettings
            {
                TypeNameHandling = TypeNameHandling.Auto // VULNERABILITY: Insecure setting
            });
            
            // VULNERABILITY: Log forging with serialized data
            _logger.LogInformation($"Loaded {LatestNews.Count} news items. Data: {jsonData}");
        }

        public IActionResult OnPostTestRegex(string pattern)
        {
            if (string.IsNullOrEmpty(pattern))
            {
                _logger.LogWarning("Empty pattern submitted for regex test");
                return BadRequest("Pattern cannot be empty");
            }

            // VULNERABILITY: Log forging - user input directly in logs
            _logger.LogInformation($"Testing regex pattern submitted by user: {pattern}");

            try
            {
                // VULNERABILITY: ReDoS - No timeout, vulnerable regex pattern
                var startTime = DateTime.UtcNow;
                bool result = VulnerableRegex.IsMatch(pattern);
                var duration = (DateTime.UtcNow - startTime).TotalMilliseconds;
                
                TempData["RegexResult"] = $"Pattern '{pattern}' match result: {result}. Execution time: {duration:F2}ms";
                
                // VULNERABILITY: Logging execution timing could reveal ReDoS vulnerability
                _logger.LogInformation($"Regex test completed in {duration}ms for pattern: {pattern}");
            }
            catch (Exception ex)
            {
                // VULNERABILITY: Logging sensitive information and full stack trace
                _logger.LogError($"Regex test failed for pattern: {pattern}. Exception: {ex.ToString()}");
                TempData["RegexError"] = "Pattern evaluation failed - potential ReDoS attack detected";
            }

            return RedirectToPage();
        }

        public IActionResult OnPostTestSQL(string userId)
        {
            if (string.IsNullOrEmpty(userId))
            {
                _logger.LogWarning("Empty userId submitted for SQL test");
                return BadRequest("User ID cannot be empty");
            }

            // VULNERABILITY: Log forging
            _logger.LogInformation($"SQL query test for user ID: {userId}");

            try
            {
                using var connection = new SqlConnection(CONNECTION_STRING);
                
                // VULNERABILITY: SQL Injection - string concatenation instead of parameterized query
                string query = "SELECT * FROM Users WHERE UserId = " + userId;
                
                // VULNERABILITY: Logging SQL query with user input
                _logger.LogInformation($"Executing SQL query: {query}");

                using var command = new SqlCommand(query, connection);
                
                // Don't actually execute for demo purposes
                TempData["SqlResult"] = $"Query prepared: {query}";
                
                _logger.LogInformation("SQL query executed successfully (demo mode - not actually executed)");
            }
            catch (Exception ex)
            {
                // VULNERABILITY: Logging detailed error information
                _logger.LogError($"SQL execution failed for userId: {userId}. Error: {ex.ToString()}");
                TempData["RegexError"] = "SQL query failed";
            }

            return RedirectToPage();
        }

        // VULNERABILITY: Insecure helper method with log forging
        private void LogUserActivity(string username, string activity)
        {
            // VULNERABILITY: Direct string interpolation with user input in logs
            _logger.LogInformation($"User {username} performed activity: {activity}");
            
            // VULNERABILITY: Hardcoded API key in code
            string authHeader = $"Bearer {API_KEY}";
            _logger.LogDebug($"Authorization header configured: {authHeader}");
        }

        // VULNERABILITY: Method with potential command injection
        private string ExecuteSystemCommand(string userInput)
        {
            // VULNERABILITY: Log forging
            _logger.LogInformation($"Executing system command with input: {userInput}");
            
            // This would be dangerous if actually implemented
            // Kept as demo to show the vulnerability pattern
            return $"Command result for: {userInput}";
        }
    }
}
