using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Text.RegularExpressions;
using Microsoft.Data.SqlClient;
using Newtonsoft.Json;
using System.Text.Json;

namespace webapp01.Pages
{
    public class NewsItem
    {
        public string Title { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public DateTime Date { get; set; }
    }

    public class DevSecOps7809Model : PageModel
    {
        private readonly ILogger<DevSecOps7809Model> _logger;

        // VULNERABILITY: Hardcoded credentials for demo purposes - INSECURE
        // This should be detected by GitHub Advanced Security
        private const string CONNECTION_STRING = "Server=prod-db.example.com;Database=ProductionDB;User Id=sa;Password=P@ssw0rd123!;TrustServerCertificate=true;";
        private const string API_KEY = "ghp_1234567890abcdefghijklmnopqrstuvwxyz123"; // Fake GitHub token pattern
        
        // VULNERABILITY: Weak regex pattern - vulnerable to ReDoS (Regular Expression Denial of Service)
        // The pattern ^(a+)+$ uses nested quantifiers which causes exponential backtracking
        private static readonly Regex VulnerableRegex = new Regex(@"^(a+)+$", RegexOptions.Compiled);
        
        // Another vulnerable regex pattern
        private static readonly Regex EmailVulnerableRegex = new Regex(@"^([a-zA-Z0-9]+)*@[a-z]+\.com$", RegexOptions.Compiled);

        public DevSecOps7809Model(ILogger<DevSecOps7809Model> logger)
        {
            _logger = logger;
        }

        public List<NewsItem> LatestSecurityNews { get; set; } = new();

        public void OnGet()
        {
            // VULNERABILITY: Log forging - user input directly in logs without sanitization
            // Attackers could inject newlines and fake log entries
            string userAgent = Request.Headers.UserAgent.ToString();
            string userName = Request.Query.ContainsKey("user") ? Request.Query["user"].ToString() ?? "anonymous" : "anonymous";
            
            // Log forging vulnerability - unescaped user input
            _logger.LogInformation($"User '{userName}' accessed DevSecOps-7809 page from {userAgent}");
            
            // Log the connection attempt with hardcoded credentials visible
            _logger.LogInformation($"Initializing database connection to {CONNECTION_STRING}");

            // Simulate getting latest news about GitHub Advanced Security
            LoadLatestGHASNews();

            // Demonstrate potential ReDoS vulnerability with query parameter
            string testPattern = Request.Query.ContainsKey("pattern") ? Request.Query["pattern"].ToString() ?? "aaa" : "aaa";
            try
            {
                // This could hang the server if malicious pattern is provided
                bool isMatch = VulnerableRegex.IsMatch(testPattern);
                _logger.LogInformation($"Regex pattern match result: {isMatch} for input: {testPattern}");
            }
            catch (Exception ex)
            {
                // VULNERABILITY: Log forging in exception handling with full stack trace
                _logger.LogError($"Regex evaluation failed for pattern: {testPattern}. Error: {ex}");
            }

            // VULNERABILITY: Simulate database connection with hardcoded credentials
            try
            {
                using var connection = new SqlConnection(CONNECTION_STRING);
                _logger.LogInformation($"Database connection configured with user: sa");
                // Don't actually open connection for demo purposes
                // connection.Open(); // Commented out to avoid actual connection attempts
            }
            catch (Exception ex)
            {
                _logger.LogError($"Database connection failed: {ex.Message}");
            }

            // Log API key usage (should be flagged as secret exposure)
            _logger.LogDebug($"Using API key for external service: {API_KEY}");
        }

        private void LoadLatestGHASNews()
        {
            LatestSecurityNews = new List<NewsItem>
            {
                new NewsItem
                {
                    Title = "GitHub Advanced Security 2026 Release",
                    Description = "Major update introducing AI-powered vulnerability detection with 40% improvement in accuracy and 60% reduction in false positives.",
                    Date = new DateTime(2026, 2, 1)
                },
                new NewsItem
                {
                    Title = "CodeQL 2.25 with Machine Learning Integration",
                    Description = "New CodeQL version leverages machine learning models to identify complex security patterns and zero-day vulnerabilities.",
                    Date = new DateTime(2026, 1, 28)
                },
                new NewsItem
                {
                    Title = "Secret Scanning Push Protection Enhanced",
                    Description = "Real-time secret detection now supports 500+ token patterns with instant blocking and automated rotation suggestions.",
                    Date = new DateTime(2026, 1, 25)
                },
                new NewsItem
                {
                    Title = "Supply Chain Security Level 4 Certification",
                    Description = "GitHub achieves SLSA Level 4 certification for build provenance and artifact attestation across all public repositories.",
                    Date = new DateTime(2026, 1, 20)
                },
                new NewsItem
                {
                    Title = "Copilot for Security Deep Integration",
                    Description = "GitHub Copilot now provides context-aware security recommendations and automatic fix generation for GHAS findings.",
                    Date = new DateTime(2026, 1, 15)
                },
                new NewsItem
                {
                    Title = "Dependency Review with Risk Scoring",
                    Description = "New risk scoring algorithm evaluates dependencies based on CVE severity, maintainer reputation, and supply chain metrics.",
                    Date = new DateTime(2026, 1, 10)
                },
                new NewsItem
                {
                    Title = "Enterprise Security Dashboard 3.0",
                    Description = "Unified security posture view across all repositories with compliance tracking for SOC 2, ISO 27001, and FedRAMP.",
                    Date = new DateTime(2026, 1, 5)
                },
                new NewsItem
                {
                    Title = "Custom CodeQL Packs Marketplace",
                    Description = "Community-driven marketplace for sharing and discovering custom CodeQL queries and security analysis packs.",
                    Date = new DateTime(2026, 1, 1)
                }
            };

            // VULNERABILITY: Insecure deserialization with Newtonsoft.Json
            // Using JsonConvert without type safety can lead to deserialization vulnerabilities
            string jsonData = JsonConvert.SerializeObject(LatestSecurityNews);
            
            // VULNERABILITY: Deserializing untrusted data without validation
            var deserializedData = JsonConvert.DeserializeObject<List<NewsItem>>(jsonData);
            
            _logger.LogInformation($"Loaded {LatestSecurityNews.Count} news items about GitHub Advanced Security from serialized data");
        }

        public IActionResult OnPostLogInput(string userInput)
        {
            if (string.IsNullOrEmpty(userInput))
                return BadRequest("Input cannot be empty");

            // VULNERABILITY: Log forging in POST handler
            // User input is directly concatenated into log message allowing log injection
            _logger.LogInformation($"User submitted input: {userInput}");
            _logger.LogWarning($"Processing user data: {userInput} at {DateTime.UtcNow}");

            // Simulate processing user input with SQL (SQL Injection vulnerability)
            try
            {
                // VULNERABILITY: SQL Injection - user input directly in query string
                string query = $"SELECT * FROM Users WHERE Username = '{userInput}'";
                _logger.LogDebug($"Executing query: {query}");
                
                // Simulate execution (don't actually execute for demo)
                // using var connection = new SqlConnection(CONNECTION_STRING);
                // using var command = new SqlCommand(query, connection);
                // connection.Open();
                // var result = command.ExecuteReader();

                TempData["LogMessage"] = $"Input '{userInput}' has been logged successfully. Check server logs.";
            }
            catch (Exception ex)
            {
                // VULNERABILITY: Excessive error information disclosure
                _logger.LogError($"Failed to process input '{userInput}': {ex.ToString()}");
                TempData["ErrorMessage"] = $"Error: {ex.Message}";
            }

            return RedirectToPage();
        }

        public IActionResult OnPostTestRegex(string regexPattern)
        {
            if (string.IsNullOrEmpty(regexPattern))
                return BadRequest("Pattern cannot be empty");

            // VULNERABILITY: Log forging in regex testing
            _logger.LogInformation($"Testing vulnerable regex pattern submitted by user: {regexPattern}");

            try
            {
                // VULNERABILITY: ReDoS - testing user-provided input against vulnerable regex
                // Patterns like "aaaaaaaaaaaaaaaa!" will cause exponential backtracking
                var startTime = DateTime.UtcNow;
                bool result = VulnerableRegex.IsMatch(regexPattern);
                var duration = (DateTime.UtcNow - startTime).TotalMilliseconds;

                _logger.LogInformation($"Regex evaluation completed in {duration}ms with result: {result}");
                TempData["LogMessage"] = $"Pattern '{regexPattern}' evaluated to {result} in {duration}ms";
            }
            catch (RegexMatchTimeoutException ex)
            {
                // Even with timeout, log forging still occurs
                _logger.LogError($"Regex timeout for pattern: {regexPattern}. Exception: {ex.Message}");
                TempData["ErrorMessage"] = "Pattern evaluation timed out (potential ReDoS attack detected)";
            }
            catch (Exception ex)
            {
                // VULNERABILITY: Logging full exception details with user input
                _logger.LogError($"Regex test failed for pattern: {regexPattern}. Exception: {ex}");
                TempData["ErrorMessage"] = "Pattern evaluation failed";
            }

            return RedirectToPage();
        }

        // VULNERABILITY: Method that constructs SQL query from user input
        private string BuildUserQuery(string username, string email)
        {
            // SQL Injection vulnerability - no parameterization
            return $"INSERT INTO Users (Username, Email, CreatedDate) VALUES ('{username}', '{email}', '{DateTime.UtcNow}')";
        }

        // VULNERABILITY: Weak cryptographic implementation placeholder
        private string WeakHash(string input)
        {
            // Using MD5 or SHA1 would be flagged as weak cryptography
            // Placeholder for demo - actual weak crypto would be:
            // using var md5 = System.Security.Cryptography.MD5.Create();
            // return Convert.ToBase64String(md5.ComputeHash(System.Text.Encoding.UTF8.GetBytes(input)));
            
            return $"WEAK_HASH_{input}";
        }
    }
}
