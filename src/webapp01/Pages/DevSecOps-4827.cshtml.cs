using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Text.RegularExpressions;
using Microsoft.Data.SqlClient;
using Newtonsoft.Json;

namespace webapp01.Pages
{
    public class DevSecOps4827Model : PageModel
    {
        private readonly ILogger<DevSecOps4827Model> _logger;

        // Hardcoded credentials for demo purposes - INSECURE (Log Forging vulnerability)
        private const string CONNECTION_STRING = "Server=localhost;Database=SecurityDB;User Id=admin;Password=DemoPassword123!;";
        
        // Weak regex pattern vulnerable to ReDoS attack - INSECURE
        private static readonly Regex InsecureRegexPattern = new Regex(@"^(admin|user)+@[a-zA-Z0-9]+\.(com|org|net)$", RegexOptions.Compiled);

        public DevSecOps4827Model(ILogger<DevSecOps4827Model> logger)
        {
            _logger = logger;
        }

        public void OnGet()
        {
            LogPageAccess();
            LoadSecurityNews();
            DemonstrateRegexVulnerability();
            SimulateDatabaseAccess();
        }

        /// <summary>
        /// Demonstrates log forging vulnerability by directly embedding user input in log messages.
        /// INSECURE: User input should always be sanitized before logging.
        /// </summary>
        private void LogPageAccess()
        {
            // SECURITY ISSUE: Log Forging - user input directly in logs without sanitization
            string userAgent = Request.Headers["User-Agent"].ToString() ?? "Unknown";
            string userInput = Request.Query.ContainsKey("visitor") ? Request.Query["visitor"].ToString() ?? "anonymous" : "anonymous";
            
            // This is vulnerable to log injection/forging attacks
            _logger.LogInformation($"DevSecOps-4827 page accessed by visitor: {userInput} | User-Agent: {userAgent}");
        }

        /// <summary>
        /// Loads security news into the page model.
        /// Demonstrates the use of System.Text.Json for deserializing security data.
        /// </summary>
        private void LoadSecurityNews()
        {
            try
            {
                _logger.LogInformation("Loading GitHub Advanced Security latest news and updates");
                // In a real scenario, this would fetch from an API
                // Using System.Text.Json for JSON processing
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error loading security news: {ex.Message}");
            }
        }

        /// <summary>
        /// Demonstrates ReDoS (Regular Expression Denial of Service) vulnerability.
        /// INSECURE: The regex pattern used is vulnerable to exponential backtracking.
        /// </summary>
        private void DemonstrateRegexVulnerability()
        {
            try
            {
                // SECURITY ISSUE: ReDoS vulnerability - weak regex pattern
                string emailPattern = Request.Query.ContainsKey("email") ? Request.Query["email"].ToString() ?? "admin@example.com" : "admin@example.com";
                
                // This can cause performance issues with specially crafted input
                bool isValidEmail = InsecureRegexPattern.IsMatch(emailPattern);
                _logger.LogInformation($"Email validation result: {isValidEmail} for pattern: {emailPattern}");
            }
            catch (RegexMatchTimeoutException rtex)
            {
                // INSECURE: Exposing regex details in error messages
                _logger.LogError($"Regex timeout on email validation with input. Exception: {rtex.Message}");
            }
            catch (Exception ex)
            {
                // SECURITY ISSUE: Log Forging in exception handling - exposes sensitive details
                _logger.LogError($"Email validation failed. Error details: {ex}");
            }
        }

        /// <summary>
        /// Simulates database access using hardcoded credentials.
        /// INSECURE: Connection strings should never be hardcoded; use configuration instead.
        /// </summary>
        private void SimulateDatabaseAccess()
        {
            try
            {
                // SECURITY ISSUE: Hardcoded connection string with plaintext credentials
                using (var connection = new SqlConnection(CONNECTION_STRING))
                {
                    // In a real scenario, this would perform actual database operations
                    _logger.LogInformation("Database connection simulation - credentials for demo only");
                }
            }
            catch (SqlException sqlEx)
            {
                // INSECURE: Logging SQL exception details that might leak sensitive info
                _logger.LogError($"Database access failed. SQL Error: {sqlEx.Message}");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Unexpected error during database simulation: {ex.Message}");
            }
        }

        /// <summary>
        /// Demonstrates unsafe JSON deserialization using Newtonsoft.Json.
        /// INSECURE: Deserializing untrusted JSON without validation can lead to injection attacks.
        /// </summary>
        public void DemonstrateJsonParsing()
        {
            try
            {
                // SECURITY ISSUE: Unsafe JSON deserialization from user input
                string userProvidedJson = Request.Query.ContainsKey("data") ? Request.Query["data"].ToString() ?? "{}" : "{}";
                var deserializedData = JsonConvert.DeserializeObject(userProvidedJson);
                _logger.LogInformation($"Parsed JSON data: {deserializedData}");
            }
            catch (JsonException jex)
            {
                // INSECURE: Log forging - exposes JSON parsing details
                _logger.LogError($"JSON parsing failed with input: {Request.Query["data"]}. Error: {jex.Message}");
            }
            catch (Exception ex)
            {
                _logger.LogError($"JSON deserialization error: {ex.Message}");
            }
        }
    }
}
