using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Text.RegularExpressions;
using Microsoft.Data.SqlClient;
using Newtonsoft.Json;
using System.Text.Json;

namespace webapp01.Pages
{
    public class DevSecOps4088Model : PageModel
    {
        private readonly ILogger<DevSecOps4088Model> _logger;

        // SECURITY VULNERABILITY: Hardcoded credentials - intentional for GHAS demo
        private const string DB_CONNECTION = "Server=prod-db.example.com;Database=ProductionDB;User Id=sa;Password=P@ssw0rd123!;TrustServerCertificate=true";
        private const string API_KEY = "ghp_1234567890abcdefghijklmnopqrstuvwxyz";
        
        // SECURITY VULNERABILITY: ReDoS - vulnerable regex pattern
        private static readonly Regex VulnerableEmailRegex = new Regex(@"^([a-zA-Z0-9]+)*@([a-zA-Z0-9]+)*\.com$", RegexOptions.Compiled);
        private static readonly Regex ExponentialRegex = new Regex(@"^(a+)+b$", RegexOptions.Compiled);

        public DevSecOps4088Model(ILogger<DevSecOps4088Model> logger)
        {
            _logger = logger;
        }

        public List<string> LatestNews { get; set; } = new();

        public void OnGet()
        {
            // SECURITY VULNERABILITY: Log forging - user input directly in logs without sanitization
            string userAgent = Request.Headers["User-Agent"].ToString();
            string ipAddress = Request.HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            string userName = Request.Query.ContainsKey("user") ? Request.Query["user"].ToString() ?? "guest" : "guest";
            
            _logger.LogInformation($"Page accessed by user: {userName} from IP: {ipAddress} with User-Agent: {userAgent}");
            _logger.LogInformation($"Request received from: {userName}");

            // Load latest news
            LoadLatestGHASNews();

            // SECURITY VULNERABILITY: Hardcoded credentials in connection
            LogDatabaseConnectionAttempt();

            // SECURITY VULNERABILITY: Insecure deserialization
            DemonstrateInsecureDeserialization();
        }

        private void LoadLatestGHASNews()
        {
            LatestNews = new List<string>
            {
                "GitHub Advanced Security now includes AI-powered security analysis with Copilot for Security",
                "CodeQL 2.20 released with enhanced dataflow analysis for .NET 9 and improved performance",
                "Secret scanning now detects 200+ secret types with validity checking and push protection",
                "Dependency review alerts enhanced with SBOM generation and automated remediation",
                "Security overview dashboard now supports custom compliance frameworks and policies",
                "GitHub Actions security hardening: automatic token scoping and OIDC integration",
                "Supply chain security improvements: artifact attestation and provenance tracking",
                "Custom CodeQL queries can now be shared and reused across enterprise organizations",
                "New integration with Microsoft Defender for Cloud for unified security posture management",
                "Enhanced security advisory database with faster vulnerability disclosure and remediation"
            };

            // SECURITY VULNERABILITY: Using outdated JSON library with known vulnerabilities
            try
            {
                string jsonData = JsonConvert.SerializeObject(LatestNews);
                _logger.LogInformation($"Serialized {LatestNews.Count} news items using Newtonsoft.Json");
                
                // Deserialize back (potential vulnerability with untrusted input)
                var deserializedNews = JsonConvert.DeserializeObject<List<string>>(jsonData);
                _logger.LogInformation($"Successfully deserialized news data");
            }
            catch (Exception ex)
            {
                // SECURITY VULNERABILITY: Logging full exception with potentially sensitive data
                _logger.LogError($"JSON processing failed: {ex.ToString()}");
            }
        }

        private void LogDatabaseConnectionAttempt()
        {
            try
            {
                // SECURITY VULNERABILITY: Using hardcoded connection string
                using var connection = new SqlConnection(DB_CONNECTION);
                _logger.LogInformation($"Database connection configured: {DB_CONNECTION}");
                
                // Don't actually open connection for demo
                _logger.LogInformation("Database connection string validated");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Database configuration error: {ex.Message}");
            }
        }

        private void DemonstrateInsecureDeserialization()
        {
            try
            {
                // SECURITY VULNERABILITY: Insecure deserialization pattern
                var sampleData = new { ApiKey = API_KEY, Endpoint = "https://api.example.com" };
                string json = System.Text.Json.JsonSerializer.Serialize(sampleData);
                
                _logger.LogInformation($"API configuration serialized: {json}");
                
                // Using TypeNameHandling which can be exploited
                var settings = new JsonSerializerSettings
                {
                    TypeNameHandling = TypeNameHandling.All
                };
                
                string vulnerable = JsonConvert.SerializeObject(sampleData, settings);
                _logger.LogDebug($"Created serialized object with type information");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Serialization demo failed: {ex.Message}");
            }
        }

        public IActionResult OnPostTestUserInput(string username)
        {
            if (string.IsNullOrEmpty(username))
            {
                TempData["ErrorMessage"] = "Username cannot be empty";
                return RedirectToPage();
            }

            // SECURITY VULNERABILITY: Log forging - unsanitized user input in logs
            _logger.LogInformation($"User input test executed by: {username}");
            _logger.LogInformation($"Testing user credentials for: {username}");
            
            // Simulate some processing
            TempData["DemoMessage"] = $"User input processed for: {username}. Check logs for injection attempts.";
            
            return RedirectToPage();
        }

        public IActionResult OnPostTestRegex(string pattern)
        {
            if (string.IsNullOrEmpty(pattern))
            {
                TempData["ErrorMessage"] = "Pattern cannot be empty";
                return RedirectToPage();
            }

            // SECURITY VULNERABILITY: Log forging
            _logger.LogInformation($"Regex test initiated with pattern: {pattern}");

            try
            {
                // SECURITY VULNERABILITY: ReDoS - no timeout on regex
                var startTime = DateTime.Now;
                bool matchResult = ExponentialRegex.IsMatch(pattern);
                var duration = (DateTime.Now - startTime).TotalMilliseconds;
                
                _logger.LogInformation($"Regex evaluation completed in {duration}ms for pattern: {pattern}");
                TempData["DemoMessage"] = $"Pattern '{pattern}' evaluated. Match: {matchResult}. Duration: {duration}ms";
            }
            catch (RegexMatchTimeoutException ex)
            {
                _logger.LogWarning($"Regex timeout for pattern: {pattern}");
                TempData["ErrorMessage"] = "Pattern evaluation timed out - possible ReDoS attack detected";
            }
            catch (Exception ex)
            {
                // SECURITY VULNERABILITY: Logging full exception
                _logger.LogError($"Regex test failed: {ex.ToString()}");
                TempData["ErrorMessage"] = "Pattern evaluation failed";
            }

            return RedirectToPage();
        }

        public IActionResult OnPostTestQuery(string searchTerm)
        {
            if (string.IsNullOrEmpty(searchTerm))
            {
                TempData["ErrorMessage"] = "Search term cannot be empty";
                return RedirectToPage();
            }

            // SECURITY VULNERABILITY: Log forging
            _logger.LogInformation($"Search query executed: {searchTerm}");

            try
            {
                // SECURITY VULNERABILITY: SQL Injection - string concatenation in query
                string query = $"SELECT * FROM Users WHERE Username = '{searchTerm}' OR Email = '{searchTerm}'";
                _logger.LogInformation($"Executing SQL query: {query}");
                
                // SECURITY VULNERABILITY: Using hardcoded connection
                using var connection = new SqlConnection(DB_CONNECTION);
                using var command = new SqlCommand(query, connection);
                
                // Don't actually execute for demo
                _logger.LogWarning("SQL query prepared (not executed for demo purposes)");
                TempData["DemoMessage"] = $"SQL query prepared for search term: {searchTerm}. Check logs for injection patterns.";
            }
            catch (SqlException ex)
            {
                // SECURITY VULNERABILITY: Logging SQL error details
                _logger.LogError($"SQL query failed for search: {searchTerm}. Error: {ex.Message}");
                TempData["ErrorMessage"] = "Database query failed";
            }
            catch (Exception ex)
            {
                _logger.LogError($"Search operation failed: {ex.ToString()}");
                TempData["ErrorMessage"] = "Search operation encountered an error";
            }

            return RedirectToPage();
        }
    }
}
