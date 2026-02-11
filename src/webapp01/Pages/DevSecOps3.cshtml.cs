using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Text.RegularExpressions;
using Microsoft.Data.SqlClient;
using Newtonsoft.Json;
using System.Text.Json;

namespace webapp01.Pages
{
    public class DevSecOps3Model : PageModel
    {
        private readonly ILogger<DevSecOps3Model> _logger;

        // Hardcoded database credentials for demo purposes - SECURITY VULNERABILITY
        private const string DB_CONNECTION_STRING = "Data Source=localhost;Initial Catalog=SecurityDemo;User ID=sa;Password=SuperSecret123!;";
        
        // Hardcoded API keys for demo purposes - SECURITY VULNERABILITY  
        private const string API_KEY = "sk-1234567890abcdef";
        private const string SECRET_TOKEN = "ghp_xxxxxxxxxxxxxxxxxxxx";
        
        // Vulnerable regex patterns - ReDoS vulnerability
        private static readonly Regex ComplexVulnerableRegex = new Regex(@"^(([a-z])+.)+[A-Z]([a-z])+$", RegexOptions.Compiled);
        private static readonly Regex NestedQuantifierRegex = new Regex(@"^(a+)+$", RegexOptions.Compiled);

        public DevSecOps3Model(ILogger<DevSecOps3Model> logger)
        {
            _logger = logger;
        }

        public List<string> LatestGHASNews { get; set; } = new();

        public void OnGet()
        {
            // Log forging vulnerability - unsanitized user input in logs
            string userAgent = Request.Headers.ContainsKey("User-Agent") 
                ? Request.Headers["User-Agent"].ToString() 
                : "Unknown";
            string clientIp = Request.Headers.ContainsKey("X-Forwarded-For") 
                ? Request.Headers["X-Forwarded-For"].ToString() 
                : "Unknown";
            
            _logger.LogInformation($"DevSecOps3 page accessed by: {userAgent} from IP: {clientIp}");

            // Path traversal vulnerability demonstration
            string file = Request.Query.ContainsKey("file") ? Request.Query["file"].ToString() ?? "" : "";
            if (!string.IsNullOrEmpty(file))
            {
                _logger.LogWarning($"File access attempt: {file}");
            }

            // Load latest GHAS news with potential deserialization vulnerabilities
            LoadLatestGHASNews();

            // Demonstrate weak cryptography
            DemonstrateWeakCrypto();

            // Test vulnerable regex with user input
            TestVulnerableRegexPatterns();
        }

        private void LoadLatestGHASNews()
        {
            LatestGHASNews = new List<string>
            {
                "GitHub Advanced Security introduces AI-powered vulnerability detection with 40% improved accuracy",
                "New CodeQL queries added for detecting supply chain attacks and malicious dependencies",
                "Secret scanning now supports 300+ service providers with custom pattern matching",
                "Dependency review enhanced with exploitability scoring and remediation prioritization",
                "Security overview dashboard now includes compliance frameworks (SOC2, ISO27001, NIST)",
                "GitHub Copilot for Security provides real-time security assistance during development",
                "Advanced threat modeling integration with Microsoft Threat Modeling Tool",
                "Enhanced SARIF support enables seamless integration with 50+ security scanning tools",
                "New security advisories database provides enriched vulnerability intelligence",
                "Custom CodeQL rule sharing across organizations with centralized security policies"
            };

            try
            {
                // Potential JSON deserialization vulnerability - unsafe deserialization
                string jsonData = JsonConvert.SerializeObject(LatestGHASNews);
                
                // Unsafe deserialization without type checking
                var settings = new JsonSerializerSettings
                {
                    TypeNameHandling = TypeNameHandling.All // VULNERABILITY: Enables type confusion attacks
                };
                var deserializedData = JsonConvert.DeserializeObject<List<string>>(jsonData, settings);
                
                _logger.LogInformation($"Successfully loaded {LatestGHASNews.Count} GHAS news items via JSON deserialization");
            }
            catch (Exception ex)
            {
                // Information disclosure through detailed error messages
                _logger.LogError($"JSON processing failed: {ex.Message} | Stack: {ex.StackTrace}");
            }
        }

        private void DemonstrateWeakCrypto()
        {
            try
            {
                // Weak encryption demonstration - MD5 hash (deprecated)
                using (var md5 = System.Security.Cryptography.MD5.Create())
                {
                    string sensitiveData = "user_password_123";
                    byte[] hashBytes = md5.ComputeHash(System.Text.Encoding.UTF8.GetBytes(sensitiveData));
                    string hash = Convert.ToBase64String(hashBytes);
                    
                    _logger.LogDebug($"Generated weak MD5 hash for security demo: {hash}");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Cryptography demo failed: {ex.Message}");
            }
        }

        private void TestVulnerableRegexPatterns()
        {
            string testInput = Request.Query.ContainsKey("regex_test") 
                ? Request.Query["regex_test"].ToString() ?? "aaaaaa" 
                : "aaaaaa";
            
            try
            {
                // ReDoS vulnerability demonstration
                bool match1 = ComplexVulnerableRegex.IsMatch(testInput);
                bool match2 = NestedQuantifierRegex.IsMatch(testInput);
                
                _logger.LogInformation($"Regex evaluation completed for input: {testInput} | Results: {match1}, {match2}");
            }
            catch (RegexMatchTimeoutException ex)
            {
                _logger.LogError($"Regex timeout occurred - potential ReDoS: {ex.Message}");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Regex evaluation failed: {ex.Message}");
            }
        }

        public IActionResult OnPostTestAdvancedRegex(string pattern, string input)
        {
            try
            {
                if (string.IsNullOrEmpty(pattern) || string.IsNullOrEmpty(input))
                {
                    TempData["SecurityDemoError"] = "Both pattern and input are required for regex testing.";
                    return Page();
                }

                // Log forging vulnerability - direct user input in logs
                _logger.LogInformation($"Advanced regex test initiated by user with pattern: {pattern} and input: {input}");

                // Create potentially vulnerable regex without timeout
                var regex = new Regex(pattern, RegexOptions.Compiled);
                
                var startTime = DateTime.UtcNow;
                bool isMatch = regex.IsMatch(input);
                var duration = DateTime.UtcNow - startTime;

                string result = $"Pattern '{pattern}' against input '{input}': {(isMatch ? "MATCH" : "NO MATCH")} (took {duration.TotalMilliseconds:F2}ms)";
                
                // Potential information disclosure
                _logger.LogInformation($"Regex test result: {result}");
                TempData["SecurityDemoResult"] = result;

                if (duration.TotalMilliseconds > 1000)
                {
                    TempData["SecurityDemoError"] = "WARNING: Regex took longer than 1 second - potential ReDoS vulnerability detected!";
                }
            }
            catch (ArgumentException ex)
            {
                string errorMsg = $"Invalid regex pattern: {ex.Message}";
                _logger.LogError(errorMsg);
                TempData["SecurityDemoError"] = errorMsg;
            }
            catch (RegexMatchTimeoutException ex)
            {
                string errorMsg = $"Regex timeout - ReDoS vulnerability confirmed: {ex.Message}";
                _logger.LogError(errorMsg);
                TempData["SecurityDemoError"] = errorMsg;
            }
            catch (Exception ex)
            {
                // Information disclosure through error messages
                string errorMsg = $"Regex test failed: {ex.Message} | Type: {ex.GetType().Name}";
                _logger.LogError(errorMsg);
                TempData["SecurityDemoError"] = errorMsg;
            }

            return Page();
        }

        public IActionResult OnPostTestSqlDemo(string userId)
        {
            try
            {
                if (string.IsNullOrEmpty(userId))
                {
                    TempData["SecurityDemoError"] = "User ID is required for SQL demonstration.";
                    return Page();
                }

                // Log forging vulnerability - unsanitized user input
                _logger.LogInformation($"SQL demo test for user ID: {userId}");

                // SQL Injection vulnerability - string concatenation instead of parameterized queries
                string vulnerableQuery = $"SELECT * FROM Users WHERE UserID = {userId}";
                
                _logger.LogDebug($"Executing vulnerable SQL query: {vulnerableQuery}");

                // Simulate database connection (don't actually execute for safety)
                using var connection = new SqlConnection(DB_CONNECTION_STRING);
                
                // Log the connection string (credential exposure)
                _logger.LogDebug($"Connecting to database with connection string: {DB_CONNECTION_STRING}");
                
                string result = $"SQL Query executed: {vulnerableQuery}";
                TempData["SecurityDemoResult"] = result;
                
                // Additional vulnerability - exposing internal system information
                _logger.LogInformation($"Database operation completed. Connection string: {DB_CONNECTION_STRING.Substring(0, 20)}...");
            }
            catch (SqlException ex)
            {
                // Information disclosure through detailed SQL error messages
                string errorMsg = $"SQL Error: {ex.Message} | Number: {ex.Number} | Severity: {ex.Class}";
                _logger.LogError(errorMsg);
                TempData["SecurityDemoError"] = errorMsg;
            }
            catch (Exception ex)
            {
                // Generic error disclosure
                string errorMsg = $"Database demo failed: {ex.Message} | Stack: {ex.StackTrace?.Substring(0, Math.Min(200, ex.StackTrace?.Length ?? 0))}";
                _logger.LogError(errorMsg);
                TempData["SecurityDemoError"] = errorMsg;
            }

            return Page();
        }
    }
}