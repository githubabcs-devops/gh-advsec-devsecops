using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Text.RegularExpressions;
using Microsoft.Data.SqlClient;
using Newtonsoft.Json;
using System.Text.Json;

namespace webapp01.Pages
{
    // Model class for security news items
    public class SecurityNewsItem
    {
        public string Title { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string Category { get; set; } = string.Empty;
        public string Date { get; set; } = string.Empty;
    }

    public class DevSecOps2649Model : PageModel
    {
        private readonly ILogger<DevSecOps2649Model> _logger;

        // SECURITY VULNERABILITY: Hardcoded database credentials - should be detected by GHAS
        private const string DB_CONNECTION = "Server=prod-db.example.com;Database=ProductionDB;User Id=dbadmin;Password=P@ssw0rd123!Secure;TrustServerCertificate=true;";
        private const string API_KEY = "demo_api_key_51ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop1234567890_FOR_TESTING_ONLY";
        
        // SECURITY VULNERABILITY: Vulnerable regex pattern susceptible to ReDoS (Regular Expression Denial of Service)
        // This pattern has exponential time complexity with nested quantifiers
        private static readonly Regex InsecureRegexPattern = new Regex(@"^(a+)+$", RegexOptions.Compiled);
        private static readonly Regex EmailValidationRegex = new Regex(@"^([a-zA-Z0-9_\-\.]+)@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.)|(([a-zA-Z0-9\-]+\.)+))([a-zA-Z]{2,4}|[0-9]{1,3})(\]?)$", RegexOptions.Compiled);

        public DevSecOps2649Model(ILogger<DevSecOps2649Model> logger)
        {
            _logger = logger;
            _logger.LogInformation("DevSecOps2649Model initialized");
        }

        public List<SecurityNewsItem> LatestSecurityNews { get; set; } = new();
        public int VulnerabilitiesDetected { get; set; }
        public int AlertsResolved { get; set; }
        public int SecretsFound { get; set; }
        public int DependencyAlerts { get; set; }

        public void OnGet()
        {
            // SECURITY VULNERABILITY: Log forging - unsanitized user input in logs
            // User can inject newlines and fake log entries
            string userAgent = Request.Headers["User-Agent"].ToString();
            string ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            string userId = Request.Query.ContainsKey("userId") ? Request.Query["userId"].ToString() ?? "anonymous" : "anonymous";
            
            // Log forging vulnerability - user input directly concatenated into log message
            _logger.LogInformation($"Page accessed by user: {userId} from IP: {ipAddress} with User-Agent: {userAgent}");

            // Load GHAS news and statistics
            LoadLatestSecurityNews();
            LoadSecurityStatistics();

            // Demonstrate vulnerable database connection attempt
            AttemptDatabaseConnection();

            // Log API key usage (SECURITY VULNERABILITY: logging sensitive data)
            _logger.LogWarning($"API Key in use: {API_KEY.Substring(0, 10)}... (truncated for security)");
        }

        private void LoadLatestSecurityNews()
        {
            LatestSecurityNews = new List<SecurityNewsItem>
            {
                new SecurityNewsItem
                {
                    Title = "GitHub Copilot for Security Now Generally Available",
                    Description = "AI-powered security analysis and remediation suggestions integrated directly into your workflow with natural language queries.",
                    Category = "AI Security",
                    Date = "January 2026"
                },
                new SecurityNewsItem
                {
                    Title = "CodeQL 2.20 Released with Enhanced C# Support",
                    Description = "Improved analysis for .NET 9 applications, better LINQ query detection, and 40+ new security queries for modern C# patterns.",
                    Category = "Code Scanning",
                    Date = "December 2025"
                },
                new SecurityNewsItem
                {
                    Title = "Secret Scanning Push Protection for All Repositories",
                    Description = "Real-time protection prevents secrets from being committed across public and private repositories with 300+ partner patterns.",
                    Category = "Secret Scanning",
                    Date = "November 2025"
                },
                new SecurityNewsItem
                {
                    Title = "GHAS Now Supports Software Bill of Materials (SBOM) Export",
                    Description = "Generate comprehensive SBOMs in SPDX and CycloneDX formats for compliance and supply chain security requirements.",
                    Category = "Supply Chain",
                    Date = "October 2025"
                },
                new SecurityNewsItem
                {
                    Title = "Advanced Security Dashboard Enhancements",
                    Description = "New visualizations for security trends, team performance metrics, and compliance tracking across enterprise organizations.",
                    Category = "Platform",
                    Date = "September 2025"
                },
                new SecurityNewsItem
                {
                    Title = "Custom Security Policies with Policy as Code",
                    Description = "Define and enforce organization-wide security standards using declarative YAML configurations and automated policy checks.",
                    Category = "Governance",
                    Date = "August 2025"
                }
            };

            // SECURITY VULNERABILITY: Potential insecure deserialization
            // Serializing and deserializing without type validation
            try
            {
                string jsonData = JsonConvert.SerializeObject(LatestSecurityNews);
                var deserializedNews = JsonConvert.DeserializeObject<List<SecurityNewsItem>>(jsonData);
                
                // Log forging in the count
                _logger.LogInformation($"Loaded {LatestSecurityNews.Count} security news items for display");
            }
            catch (Exception ex)
            {
                // SECURITY VULNERABILITY: Logging full exception details including stack trace
                _logger.LogError($"Failed to process security news: {ex.ToString()}");
            }
        }

        private void LoadSecurityStatistics()
        {
            // Simulated statistics for demo purposes
            VulnerabilitiesDetected = 147;
            AlertsResolved = 132;
            SecretsFound = 23;
            DependencyAlerts = 89;

            _logger.LogInformation($"Security statistics loaded: {VulnerabilitiesDetected} vulnerabilities, {AlertsResolved} resolved, {SecretsFound} secrets, {DependencyAlerts} dependency alerts");
        }

        private void AttemptDatabaseConnection()
        {
            // SECURITY VULNERABILITY: Using hardcoded connection string with credentials
            try
            {
                using var connection = new SqlConnection(DB_CONNECTION);
                _logger.LogInformation("Attempting to establish database connection...");
                
                // Don't actually connect for demo purposes
                // connection.Open();
                
                _logger.LogInformation("Database connection string configured (not opened for demo safety)");
            }
            catch (Exception ex)
            {
                // SECURITY VULNERABILITY: Logging exception with potentially sensitive information
                _logger.LogError($"Database connection failed: {ex.Message} - Connection string: {DB_CONNECTION}");
            }
        }

        public IActionResult OnPostTestLogForging(string username)
        {
            if (string.IsNullOrEmpty(username))
            {
                TempData["LogResult"] = "Username cannot be empty";
                return RedirectToPage();
            }

            // SECURITY VULNERABILITY: Log forging/injection vulnerability
            // User can inject newlines and fake log entries: e.g., "admin\nINFO: User hacker logged in successfully"
            _logger.LogWarning($"User login attempt: {username}");
            _logger.LogInformation($"Processing request for user: {username} at {DateTime.UtcNow}");

            // Simulate authentication check with unsanitized logging
            bool isAuthenticated = username.Length > 3;
            
            if (isAuthenticated)
            {
                _logger.LogInformation($"Authentication successful for user: {username}");
                TempData["LogResult"] = $"Log entry created for user: {username}. Check server logs to see the injection.";
            }
            else
            {
                _logger.LogWarning($"Authentication failed for user: {username}");
                TempData["LogResult"] = $"Login failed for: {username}";
            }

            return RedirectToPage();
        }

        public IActionResult OnPostTestRegexVulnerability(string regexInput)
        {
            if (string.IsNullOrEmpty(regexInput))
            {
                TempData["RegexTestResult"] = "Input cannot be empty";
                return RedirectToPage();
            }

            // SECURITY VULNERABILITY: Log forging in regex test
            _logger.LogInformation($"Testing regex pattern against input: {regexInput}");

            try
            {
                // SECURITY VULNERABILITY: ReDoS (Regular Expression Denial of Service)
                // The pattern ^(a+)+$ has catastrophic backtracking
                // Input like "aaaaaaaaaaaaaaaa!" causes exponential time complexity
                var startTime = DateTime.UtcNow;
                
                bool matchResult = InsecureRegexPattern.IsMatch(regexInput);
                
                var duration = (DateTime.UtcNow - startTime).TotalMilliseconds;

                _logger.LogInformation($"Regex evaluation completed in {duration}ms with result: {matchResult}");
                
                TempData["RegexTestResult"] = $"Pattern match result: {matchResult} (took {duration:F2}ms)";
                
                // If it took a long time, warn about ReDoS
                if (duration > 1000)
                {
                    _logger.LogWarning($"ALERT: Regex evaluation took {duration}ms - possible ReDoS attack detected!");
                    TempData["RegexTestResult"] = $"⚠️ ReDoS Detected! Pattern took {duration:F0}ms to evaluate. This demonstrates a vulnerability.";
                }
            }
            catch (RegexMatchTimeoutException ex)
            {
                _logger.LogError($"Regex timeout exception: {ex.Message} for input: {regexInput}");
                TempData["RegexTestResult"] = "Regex evaluation timed out - ReDoS vulnerability demonstrated!";
            }
            catch (Exception ex)
            {
                // SECURITY VULNERABILITY: Logging full exception details
                _logger.LogError($"Regex evaluation failed: {ex.ToString()}");
                TempData["RegexTestResult"] = $"Error during regex evaluation: {ex.Message}";
            }

            return RedirectToPage();
        }

        // Additional vulnerable method for SQL injection demonstration
        private List<string> GetUserDataUnsafe(string userId)
        {
            // SECURITY VULNERABILITY: SQL Injection vulnerability
            // Never construct SQL queries with string concatenation!
            var results = new List<string>();
            
            try
            {
                using var connection = new SqlConnection(DB_CONNECTION);
                // This is intentionally vulnerable - DO NOT USE IN PRODUCTION
                string unsafeQuery = $"SELECT * FROM Users WHERE UserId = '{userId}'";
                
                _logger.LogDebug($"Executing query: {unsafeQuery}");
                
                // Not actually executing for demo safety
                // using var command = new SqlCommand(unsafeQuery, connection);
                // connection.Open();
                // var reader = command.ExecuteReader();
                
                _logger.LogWarning("SQL query constructed with string concatenation - VULNERABLE TO SQL INJECTION");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Database query failed: {ex}");
            }

            return results;
        }
    }
}
