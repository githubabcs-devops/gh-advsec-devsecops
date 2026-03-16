using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Text.RegularExpressions;
using Microsoft.Data.SqlClient;
using Newtonsoft.Json;
using System.Text.Json;

namespace webapp01.Pages
{
    public class DevSecOps4Model : PageModel
    {
        private readonly ILogger<DevSecOps4Model> _logger;

        // SECURITY VULNERABILITY: Hardcoded credentials for demo purposes - INSECURE
        private const string CONNECTION_STRING = "Server=localhost;Database=TestDB;User Id=admin;Password=SuperSecret123!;Trusted_Connection=false;";
        
        // SECURITY VULNERABILITY: Weak regex pattern - vulnerable to ReDoS (Regular Expression Denial of Service)
        private static readonly Regex VulnerableRegex = new Regex(@"^(a+)+$", RegexOptions.Compiled);
        
        // SECURITY VULNERABILITY: Another ReDoS pattern for advanced testing
        private static readonly Regex NestedQuantifierRegex = new Regex(@"^(a|b)*a*$", RegexOptions.Compiled);

        // SECURITY VULNERABILITY: Hardcoded API key for demo
        private const string API_KEY = "sk-1234567890abcdef1234567890abcdef";

        public DevSecOps4Model(ILogger<DevSecOps4Model> logger)
        {
            _logger = logger;
        }

        public List<string> LatestNews { get; set; } = new();
        public int VulnerabilityCount => 8; // Demo count
        public int NewsCount => LatestNews?.Count ?? 0;

        public void OnGet()
        {
            // SECURITY VULNERABILITY: Log forging vulnerability - user input directly in logs
            string userInput = Request.Query.ContainsKey("user") ? Request.Query["user"].ToString() ?? "anonymous" : "anonymous";
            _logger.LogInformation($"User accessed DevSecOps 4.0 page: {userInput}");

            // SECURITY VULNERABILITY: Potential information disclosure in logs
            string clientIp = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            _logger.LogInformation($"Client IP: {clientIp} accessed sensitive page at {DateTime.UtcNow}");

            // Load latest news about GitHub Advanced Security
            LoadLatestGHASNews();

            // SECURITY VULNERABILITY: Demonstrate potential ReDoS vulnerability
            string testPattern = Request.Query.ContainsKey("pattern") ? Request.Query["pattern"].ToString() ?? "aaa" : "aaa";
            try
            {
                bool isMatch = VulnerableRegex.IsMatch(testPattern);
                _logger.LogInformation($"Regex pattern match result: {isMatch} for input: {testPattern}");
            }
            catch (Exception ex)
            {
                // SECURITY VULNERABILITY: Log forging in exception handling
                _logger.LogError($"Regex evaluation failed for pattern: {testPattern}. Error: {ex.Message}");
            }

            // SECURITY VULNERABILITY: Simulate database connection with hardcoded credentials
            try
            {
                using var connection = new SqlConnection(CONNECTION_STRING);
                _logger.LogInformation("Attempting database connection with hardcoded credentials...");
                // Don't actually open connection for demo purposes
                
                // SECURITY VULNERABILITY: SQL injection potential
                string userId = Request.Query.ContainsKey("userId") ? Request.Query["userId"].ToString() ?? "1" : "1";
                string sqlQuery = $"SELECT * FROM Users WHERE Id = {userId}"; // Vulnerable to SQL injection
                _logger.LogWarning($"Executing potentially vulnerable SQL query: {sqlQuery}");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Database connection failed: {ex.Message}");
            }

            // SECURITY VULNERABILITY: Demonstrate weak cryptography
            DemonstrateWeakCrypto();
        }

        private void LoadLatestGHASNews()
        {
            LatestNews = new List<string>
            {
                "GitHub Advanced Security 4.0 now features AI-powered vulnerability detection with 99.5% accuracy",
                "New CodeQL engine supports 15+ additional programming languages including Rust and Kotlin",
                "Secret scanning now detects 500+ new token patterns with zero false positives",
                "Dependency review alerts include automated remediation suggestions with pull request generation",
                "Security advisories integration enhanced with real-time threat intelligence feeds",
                "AI-powered security suggestions available in GitHub Copilot for Security with natural language queries",
                "New compliance frameworks: SOC 2, PCI DSS, and HIPAA integrated in security overview dashboard",
                "Enhanced SARIF 2.1.0 support for seamless third-party security tools integration",
                "Container scanning now includes runtime vulnerability detection and base image recommendations",
                "Advanced security workflows support custom policies and automated security gates"
            };

            // SECURITY VULNERABILITY: Potential JSON deserialization vulnerability
            try
            {
                string jsonData = JsonConvert.SerializeObject(LatestNews);
                var deserializedData = JsonConvert.DeserializeObject<List<string>>(jsonData);
                
                // SECURITY VULNERABILITY: Using System.Text.Json with potentially unsafe settings
                var options = new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true,
                    // This could be vulnerable depending on the data
                };
                string systemJsonData = System.Text.Json.JsonSerializer.Serialize(LatestNews, options);
                
                _logger.LogInformation($"Loaded {LatestNews.Count} news items about GitHub Advanced Security 4.0");
            }
            catch (Exception ex)
            {
                _logger.LogError($"JSON processing error: {ex.Message}");
            }
        }

        public IActionResult OnPostTestSecurity(string? userInput, string? regexPattern, string? jsonData)
        {
            try
            {
                // SECURITY VULNERABILITY: Log injection test
                if (!string.IsNullOrEmpty(userInput))
                {
                    _logger.LogInformation($"Security test with user input: {userInput}");
                    TempData["SecurityResult"] = $"Log injection test completed for input: {userInput}";
                }

                // SECURITY VULNERABILITY: ReDoS test
                if (!string.IsNullOrEmpty(regexPattern))
                {
                    var testRegex = new Regex(regexPattern, RegexOptions.Compiled, TimeSpan.FromSeconds(1));
                    bool result = testRegex.IsMatch("aaaaaaaaaaaaaaaaaaaaaa");
                    _logger.LogInformation($"Regex test result: {result} for pattern: {regexPattern}");
                    TempData["SecurityResult"] += $" | Regex test completed for pattern: {regexPattern}";
                }

                // SECURITY VULNERABILITY: JSON deserialization test
                if (!string.IsNullOrEmpty(jsonData))
                {
                    var deserialized = JsonConvert.DeserializeObject(jsonData);
                    _logger.LogInformation($"JSON deserialization test completed for data: {jsonData}");
                    TempData["SecurityResult"] += $" | JSON test completed";
                }
            }
            catch (RegexMatchTimeoutException)
            {
                TempData["SecurityError"] = "Regex pattern caused timeout - potential ReDoS vulnerability detected!";
                _logger.LogWarning("ReDoS vulnerability demonstration triggered");
            }
            catch (Exception ex)
            {
                TempData["SecurityError"] = $"Security test failed: {ex.Message}";
                _logger.LogError($"Security test error: {ex.Message}");
            }

            return RedirectToPage();
        }

        public IActionResult OnPostTestDatabase()
        {
            try
            {
                // SECURITY VULNERABILITY: Database connection with hardcoded credentials
                using var connection = new SqlConnection(CONNECTION_STRING);
                _logger.LogInformation("Testing database connection with hardcoded credentials");
                
                // SECURITY VULNERABILITY: Simulated SQL injection vulnerability
                string maliciousInput = "'; DROP TABLE Users; --";
                string vulnerableQuery = $"SELECT * FROM Users WHERE Name = '{maliciousInput}'";
                _logger.LogWarning($"Vulnerable SQL query demonstration: {vulnerableQuery}");
                
                TempData["SecurityResult"] = "Database vulnerability test completed (no actual connection made)";
            }
            catch (Exception ex)
            {
                TempData["SecurityError"] = $"Database test failed: {ex.Message}";
                _logger.LogError($"Database test error: {ex.Message}");
            }

            return RedirectToPage();
        }

        private void DemonstrateWeakCrypto()
        {
            try
            {
                // SECURITY VULNERABILITY: Weak cryptographic practices
                using var md5 = System.Security.Cryptography.MD5.Create();
                byte[] inputBytes = System.Text.Encoding.ASCII.GetBytes("sensitive-data");
                byte[] hashBytes = md5.ComputeHash(inputBytes);
                
                // SECURITY VULNERABILITY: Using weak hash algorithm
                string hash = Convert.ToHexString(hashBytes);
                _logger.LogInformation($"MD5 hash demonstration (weak algorithm): {hash}");

                // SECURITY VULNERABILITY: Hardcoded salt
                string salt = "hardcoded-salt-123";
                _logger.LogWarning($"Using hardcoded salt for hashing: {salt}");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Cryptography demonstration error: {ex.Message}");
            }
        }

        private void DemonstratePathTraversal(string userPath)
        {
            // SECURITY VULNERABILITY: Path traversal vulnerability
            try
            {
                string basePath = "/var/www/uploads/";
                string fullPath = Path.Combine(basePath, userPath);
                _logger.LogInformation($"File access attempt: {fullPath}");
                
                // This could allow access to files outside the intended directory
                if (System.IO.File.Exists(fullPath))
                {
                    _logger.LogWarning($"File access granted to: {fullPath}");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Path traversal demonstration error: {ex.Message}");
            }
        }

        private void DemonstrateXSS(string userContent)
        {
            // SECURITY VULNERABILITY: Potential XSS if not properly encoded
            _logger.LogInformation($"User content received: {userContent}");
            // In a real scenario, this content might be rendered without proper encoding
        }
    }
}