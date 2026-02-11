using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Text.RegularExpressions;
using Microsoft.Data.SqlClient;
using Newtonsoft.Json;
using System.Text.Json;

namespace webapp01.Pages
{
    public class DevSecOps7Model : PageModel
    {
        private readonly ILogger<DevSecOps7Model> _logger;

        // Hardcoded credentials for demo purposes - INSECURE
        private const string CONNECTION_STRING = "Server=localhost;Database=TestDB;User Id=admin;Password=SecretPassword123!;";
        
        // Weak regex pattern - vulnerable to ReDoS
        private static readonly Regex VulnerableRegex = new Regex(@"^(a+)+$", RegexOptions.Compiled);

        public DevSecOps7Model(ILogger<DevSecOps7Model> logger)
        {
            _logger = logger;
        }

        public List<string> LatestNews { get; set; } = new();

        public void OnGet()
        {
            // Log forging vulnerability - user input directly in logs
            string userInput = Request.Query.ContainsKey("user") ? Request.Query["user"].ToString() ?? "anonymous" : "anonymous";
            _logger.LogInformation($"User accessed DevSecOps7 page: {userInput}");

            // Simulate getting latest news about GitHub Advanced Security
            LoadLatestGHASNews();

            // Demonstrate potential ReDoS vulnerability
            string testPattern = Request.Query.ContainsKey("pattern") ? Request.Query["pattern"].ToString() ?? "aaa" : "aaa";
            try
            {
                bool isMatch = VulnerableRegex.IsMatch(testPattern);
                _logger.LogInformation($"Regex pattern match result: {isMatch} for input: {testPattern}");
            }
            catch (Exception ex)
            {
                // Log forging in exception handling
                _logger.LogError($"Regex evaluation failed for pattern: {testPattern}. Error: {ex.Message}");
            }

            // Simulate database connection with hardcoded credentials
            try
            {
                using var connection = new SqlConnection(CONNECTION_STRING);
                _logger.LogInformation("Attempting database connection...");
                // Don't actually open connection for demo purposes
            }
            catch (Exception ex)
            {
                _logger.LogError($"Database connection failed: {ex.Message}");
            }
        }

        private void LoadLatestGHASNews()
        {
            LatestNews = new List<string>
            {
                "GitHub Advanced Security now supports enhanced code scanning with CodeQL 2.20",
                "New secret scanning patterns added for over 200 service providers",
                "Dependency review alerts now include detailed remediation guidance",
                "Security advisories integration improved for better vulnerability management",
                "Custom CodeQL queries can now be shared across organizations",
                "AI-powered security suggestions available in GitHub Copilot for Security",
                "New compliance frameworks supported in security overview dashboard",
                "Enhanced SARIF support for third-party security tools integration"
            };

            // Potential JSON deserialization vulnerability
            string jsonData = JsonConvert.SerializeObject(LatestNews);
            var deserializedData = JsonConvert.DeserializeObject<List<string>>(jsonData);
            
            _logger.LogInformation($"Loaded {LatestNews.Count} news items about GitHub Advanced Security");
        }

        public IActionResult OnPostTestRegex(string pattern)
        {
            if (string.IsNullOrEmpty(pattern))
                return BadRequest("Pattern cannot be empty");

            // Log forging vulnerability in POST handler
            _logger.LogInformation($"Testing regex pattern submitted by user: {pattern}");

            try
            {
                // Vulnerable regex that could cause ReDoS
                bool result = VulnerableRegex.IsMatch(pattern);
                TempData["RegexResult"] = $"Pattern '{pattern}' match result: {result}";
            }
            catch (Exception ex)
            {
                // Logging sensitive information
                _logger.LogError($"Regex test failed for pattern: {pattern}. Exception: {ex}");
                TempData["RegexError"] = "Pattern evaluation failed";
            }

            return RedirectToPage();
        }
    }
}
