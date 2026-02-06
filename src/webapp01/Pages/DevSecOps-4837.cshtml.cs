using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Text.RegularExpressions;
using Microsoft.Data.SqlClient;
using Newtonsoft.Json;
using System.Text.Json;

namespace webapp01.Pages
{
    /// <summary>
    /// DevSecOps Demo Page Model - Contains intentional security vulnerabilities for GHAS demonstration
    /// WARNING: This code is intentionally insecure for educational purposes only
    /// </summary>
    public class DevSecOps4837Model : PageModel
    {
        private readonly ILogger<DevSecOps4837Model> _logger;

        // SECURITY ISSUE: Hardcoded database credentials - will be detected by GHAS Secret Scanning
        private const string DB_CONNECTION_STRING = "Server=demo-sql.database.windows.net;Database=GHASDemo;User Id=demoadmin;Password=P@ssw0rd123!;";
        
        // SECURITY ISSUE: Vulnerable regex pattern susceptible to ReDoS (Regular Expression Denial of Service)
        // This pattern has nested quantifiers which can cause exponential backtracking
        private static readonly Regex VulnerableEmailRegex = new Regex(@"^([a-zA-Z0-9]+)*@([a-zA-Z0-9]+)*\.com$", RegexOptions.Compiled);

        public DevSecOps4837Model(ILogger<DevSecOps4837Model> logger)
        {
            _logger = logger;
            _logger.LogInformation("DevSecOps4837Model initialized");
        }

        public List<GHASNewsItem> GHASNews { get; set; } = new List<GHASNewsItem>();

        public void OnGet()
        {
            // SECURITY ISSUE: Log Forging - Unsanitized user input directly in log statements
            string userName = Request.Query.ContainsKey("user") ? Request.Query["user"].ToString() ?? "anonymous" : "anonymous";
            _logger.LogInformation($"User {userName} accessed DevSecOps-4837 page");

            // SECURITY ISSUE: Another log forging example with query parameter
            string action = Request.Query.ContainsKey("action") ? Request.Query["action"].ToString() ?? "view" : "view";
            _logger.LogInformation($"Action performed: {action} by user {userName}");

            // Load GHAS news with intentional vulnerabilities
            LoadGHASNews();

            // Demonstrate regex vulnerability
            DemonstrateRegexVulnerability();

            // Demonstrate SQL injection risk
            DemonstrateSQLRisk();
        }

        private void LoadGHASNews()
        {
            _logger.LogInformation("Loading latest GitHub Advanced Security news");

            GHASNews = new List<GHASNewsItem>
            {
                new GHASNewsItem
                {
                    Title = "CodeQL 2.20 Released with Enhanced Security Analysis",
                    Description = "New CodeQL version includes improved support for C#, Java, and JavaScript with 50+ new security queries for OWASP Top 10 vulnerabilities.",
                    Date = DateTime.Now.AddDays(-2)
                },
                new GHASNewsItem
                {
                    Title = "Secret Scanning Push Protection Now GA",
                    Description = "Push protection prevents developers from accidentally committing secrets to repositories, with support for 200+ token patterns.",
                    Date = DateTime.Now.AddDays(-5)
                },
                new GHASNewsItem
                {
                    Title = "Dependabot Security Updates Enhanced",
                    Description = "Automated dependency updates now include intelligent PR grouping and compatibility scoring to reduce alert fatigue.",
                    Date = DateTime.Now.AddDays(-7)
                },
                new GHASNewsItem
                {
                    Title = "AI-Powered Security Fix Suggestions",
                    Description = "GitHub Copilot for Security now provides context-aware fix suggestions for code scanning alerts with one-click remediation.",
                    Date = DateTime.Now.AddDays(-10)
                },
                new GHASNewsItem
                {
                    Title = "Custom CodeQL Query Suites",
                    Description = "Organizations can now create and share custom CodeQL query suites across repositories for industry-specific compliance requirements.",
                    Date = DateTime.Now.AddDays(-14)
                },
                new GHASNewsItem
                {
                    Title = "Security Overview Dashboard Updates",
                    Description = "New metrics and visualizations for tracking security posture across enterprise organizations with improved filtering and export capabilities.",
                    Date = DateTime.Now.AddDays(-18)
                }
            };

            // SECURITY ISSUE: Unnecessary JSON serialization/deserialization that could introduce vulnerabilities
            string jsonData = JsonConvert.SerializeObject(GHASNews);
            var tempData = JsonConvert.DeserializeObject<List<GHASNewsItem>>(jsonData);
            
            _logger.LogInformation($"Loaded {GHASNews.Count} GHAS news items");
        }

        private void DemonstrateRegexVulnerability()
        {
            // SECURITY ISSUE: Testing vulnerable regex pattern that could cause ReDoS
            string testEmail = Request.Query.ContainsKey("email") ? Request.Query["email"].ToString() ?? "test@example.com" : "test@example.com";
            
            try
            {
                // This vulnerable regex can cause exponential backtracking with inputs like "aaaaaaaaaaaaaaaaaaaaaaaaa@aaaaaaaaaaaaaaa"
                bool isValidEmail = VulnerableEmailRegex.IsMatch(testEmail);
                _logger.LogInformation($"Email validation result for {testEmail}: {isValidEmail}");
            }
            catch (Exception ex)
            {
                // SECURITY ISSUE: Logging full exception details which might contain sensitive information
                _logger.LogError($"Regex validation failed for email: {testEmail}. Exception: {ex}");
            }
        }

        private void DemonstrateSQLRisk()
        {
            // SECURITY ISSUE: Using hardcoded connection string
            try
            {
                using var connection = new SqlConnection(DB_CONNECTION_STRING);
                _logger.LogInformation("Database connection configured with demo credentials");
                
                // SECURITY ISSUE: Potential SQL injection if this were to accept user input
                string userId = Request.Query.ContainsKey("userId") ? Request.Query["userId"].ToString() ?? "1" : "1";
                string unsafeQuery = $"SELECT * FROM Users WHERE UserId = {userId}"; // SQL INJECTION RISK
                
                // Log the unsafe query (for demonstration - not actually executing)
                _logger.LogWarning($"Unsafe SQL query constructed: {unsafeQuery}");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Database operation failed: {ex.Message}");
            }
        }

        public IActionResult OnPostProcessInput(string userInput)
        {
            if (string.IsNullOrEmpty(userInput))
            {
                _logger.LogWarning("Empty input received in ProcessInput handler");
                return Page();
            }

            // SECURITY ISSUE: Log Forging - User input directly in logs without sanitization
            _logger.LogInformation($"Processing user input: {userInput}");
            
            // SECURITY ISSUE: User input could contain newlines or control characters
            _logger.LogInformation($"Input length: {userInput.Length}, Content: {userInput}");

            // Demonstrate potential command injection risk (not actually executing)
            if (userInput.Contains(";") || userInput.Contains("|"))
            {
                _logger.LogWarning($"Suspicious input detected with special characters: {userInput}");
            }

            TempData["Message"] = $"Input processed: {userInput}";
            return RedirectToPage();
        }
    }

    /// <summary>
    /// Model for GHAS news items
    /// </summary>
    public class GHASNewsItem
    {
        public string Title { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public DateTime Date { get; set; }
    }
}
