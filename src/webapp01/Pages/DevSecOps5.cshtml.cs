using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Text.RegularExpressions;
using Microsoft.Data.SqlClient;
using Newtonsoft.Json;
using System.Text.Json;

namespace webapp01.Pages
{
    public class DevSecOps5Model : PageModel
    {
        private readonly ILogger<DevSecOps5Model> _logger;

        // INSECURE: Hardcoded database credentials for demo purposes
        private const string DB_CONNECTION = "Server=localhost;Database=DemoApp;User Id=admin;Password=SuperSecret123!;TrustServerCertificate=true;";
        
        // INSECURE: API Key hardcoded for demo purposes
        private const string API_KEY = "sk-demo-1234567890abcdef-NEVER-USE-IN-PROD";
        
        // INSECURE: Vulnerable regex pattern susceptible to ReDoS attacks
        private static readonly Regex VulnerableRegex = new Regex(@"^(a+)+$", RegexOptions.Compiled);
        private static readonly Regex EmailRegex = new Regex(@"^([a-zA-Z0-9])+([a-zA-Z0-9\._-])*@([a-zA-Z0-9_-])+([a-zA-Z0-9\._-]+)+$", RegexOptions.Compiled);

        public DevSecOps5Model(ILogger<DevSecOps5Model> logger)
        {
            _logger = logger;
        }

        public List<string> LatestGHASNews { get; set; } = new();
        public int VulnerabilityCount { get; set; }
        public int SecretsFound { get; set; }
        public int DependenciesScanned { get; set; }
        public string SecurityScore { get; set; } = "C+";

        public void OnGet()
        {
            // LOG FORGING: User input directly logged without sanitization
            string userAgent = Request.Headers.UserAgent.ToString();
            string ipAddress = Request.HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            string userInput = Request.Query.ContainsKey("user") ? Request.Query["user"].ToString() ?? "anonymous" : "anonymous";
            
            // INSECURE: Direct user input in logs
            _logger.LogInformation($"DevSecOps5 page accessed by user: {userInput} from IP: {ipAddress} with UserAgent: {userAgent}");

            LoadLatestGHASNews();
            GenerateSecurityStats();

            // INSECURE: Simulate database connection with hardcoded credentials
            try
            {
                // Don't actually connect for demo, but log the attempt with sensitive info
                _logger.LogInformation($"Attempting database connection to: {DB_CONNECTION}");
                _logger.LogDebug($"Using API key: {API_KEY}");
                
                using var connection = new SqlConnection(DB_CONNECTION);
                // Simulated connection - don't actually open
                
                _logger.LogInformation("Database connection simulation completed");
            }
            catch (Exception ex)
            {
                // LOG FORGING: Exception details with user input
                _logger.LogError($"Database connection failed for user {userInput}: {ex.Message}");
            }

            // INSECURE: Test vulnerable regex patterns
            TestVulnerableRegex();
        }

        private void LoadLatestGHASNews()
        {
            LatestGHASNews = new List<string>
            {
                "GitHub Advanced Security now includes AI-powered vulnerability remediation suggestions",
                "New CodeQL 2.25 with enhanced C# and .NET analysis capabilities released",
                "Secret scanning now supports 500+ new token patterns including cloud services",
                "Dependency review with automated security updates and license compliance checking",
                "Advanced threat modeling integration with STRIDE methodology support",
                "Real-time security alerts with Slack and Microsoft Teams integration",
                "Enhanced SARIF support with custom security rule definitions",
                "Supply chain security with SBOM generation and provenance tracking"
            };

            // INSECURE: Potential JSON deserialization vulnerability
            try
            {
                string jsonData = JsonConvert.SerializeObject(LatestGHASNews);
                // INSECURE: Deserializing without type validation
                var deserializedData = JsonConvert.DeserializeObject<List<string>>(jsonData);
                
                _logger.LogInformation($"Successfully loaded {LatestGHASNews.Count} latest GHAS news items");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Failed to process GHAS news: {ex.Message}");
            }
        }

        private void GenerateSecurityStats()
        {
            // Simulate security statistics
            Random rand = new Random();
            VulnerabilityCount = rand.Next(15, 25);
            SecretsFound = rand.Next(3, 8);
            DependenciesScanned = rand.Next(150, 300);
            
            string[] scores = { "A+", "A", "B+", "B", "C+", "C", "D" };
            SecurityScore = scores[rand.Next(scores.Length)];

            _logger.LogInformation($"Generated security stats - Vulnerabilities: {VulnerabilityCount}, Secrets: {SecretsFound}, Dependencies: {DependenciesScanned}, Score: {SecurityScore}");
        }

        private void TestVulnerableRegex()
        {
            // INSECURE: Testing with potentially dangerous regex patterns
            string testPattern = Request.Query.ContainsKey("pattern") ? Request.Query["pattern"].ToString() ?? "aaa" : "aaa";
            
            try
            {
                bool isMatch = VulnerableRegex.IsMatch(testPattern);
                _logger.LogInformation($"Vulnerable regex test result: {isMatch} for pattern: {testPattern}");
            }
            catch (Exception ex)
            {
                // LOG FORGING: User input in error logs
                _logger.LogError($"Regex evaluation failed for pattern: {testPattern}. Error: {ex.Message}");
            }
        }

        public IActionResult OnPostTestSql(string sqlInput)
        {
            if (!string.IsNullOrEmpty(sqlInput))
            {
                // INSECURE: Direct SQL input logging (potential injection vulnerability demo)
                _logger.LogWarning($"SQL test executed: {sqlInput}");
                
                // INSECURE: Simulated SQL injection vulnerability
                string userAgent = Request.Headers.UserAgent.ToString();
                string queryToExecute = $"SELECT * FROM logs WHERE query = '{sqlInput}' AND user_agent = '{userAgent}'";
                
                _logger.LogInformation($"Constructed query: {queryToExecute}");
                
                TempData["SecurityTest"] = $"SQL Query processed: {sqlInput} (Check logs for potential injection patterns)";
            }

            return RedirectToPage();
        }

        public IActionResult OnPostTestRegex(string regexPattern)
        {
            if (!string.IsNullOrEmpty(regexPattern))
            {
                try
                {
                    // INSECURE: User-provided regex pattern could cause ReDoS
                    var userRegex = new Regex(regexPattern, RegexOptions.Compiled);
                    string testString = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
                    
                    // LOG FORGING: User input in logs
                    _logger.LogWarning($"Testing user-provided regex pattern: {regexPattern}");
                    
                    DateTime start = DateTime.Now;
                    bool result = userRegex.IsMatch(testString);
                    TimeSpan duration = DateTime.Now - start;
                    
                    _logger.LogInformation($"Regex test completed in {duration.TotalMilliseconds}ms - Result: {result}");
                    
                    TempData["SecurityTest"] = $"Regex pattern '{regexPattern}' processed in {duration.TotalMilliseconds:F2}ms - Result: {result}";
                }
                catch (Exception ex)
                {
                    // LOG FORGING: Exception with user input
                    _logger.LogError($"Regex test failed for pattern '{regexPattern}': {ex.Message}");
                    TempData["SecurityTest"] = $"Regex test failed: {ex.Message}";
                }
            }

            return RedirectToPage();
        }
    }
}