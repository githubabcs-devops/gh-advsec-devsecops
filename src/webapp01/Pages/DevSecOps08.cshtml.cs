using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Text.RegularExpressions;
using Microsoft.Data.SqlClient;
using Newtonsoft.Json;
using System.Text.Json;

namespace webapp01.Pages
{
    public class DevSecOps08Model : PageModel
    {
        private readonly ILogger<DevSecOps08Model> _logger;

        // VULNERABILITY: Hard-coded credentials - INSECURE for demo purposes
        private const string DB_CONNECTION = "Server=myserver.database.windows.net;Database=ProductionDB;User Id=dbadmin;Password=P@ssw0rd123!;";
        private const string API_KEY = "ghp_1234567890abcdefghijklmnopqrstuvwxyz12";
        
        // VULNERABILITY: Vulnerable regex pattern susceptible to ReDoS (Regular Expression Denial of Service)
        private static readonly Regex InsecureEmailRegex = new Regex(@"^([a-zA-Z0-9])+@([a-zA-Z0-9]+\.)+[a-zA-Z]{2,}$", RegexOptions.None);
        private static readonly Regex VulnerablePattern = new Regex(@"^(a+)+b$", RegexOptions.Compiled);

        public DevSecOps08Model(ILogger<DevSecOps08Model> logger)
        {
            _logger = logger;
            _logger.LogInformation("DevSecOps08Model initialized");
        }

        public void OnGet()
        {
            _logger.LogInformation("DevSecOps08 page accessed");

            // VULNERABILITY: Log Forging - unsanitized user input in logs
            string userName = Request.Query.ContainsKey("user") ? Request.Query["user"].ToString() ?? "anonymous" : "anonymous";
            string sessionId = Request.Query.ContainsKey("session") ? Request.Query["session"].ToString() ?? "N/A" : "N/A";
            
            // Direct user input in logs without sanitization - can inject malicious log entries
            _logger.LogInformation($"User: {userName} accessed DevSecOps08 page with session: {sessionId}");
            
            // VULNERABILITY: Log forging with newline injection possibility
            string userAgent = Request.Headers.UserAgent.ToString();
            _logger.LogWarning($"Page accessed from user agent: {userAgent}");

            // Demonstrate potential database connection with hardcoded credentials
            DemonstrateInsecureDatabaseConnection();

            // Demonstrate regex vulnerability
            DemonstrateRegexVulnerability();

            // Demonstrate insecure deserialization
            DemonstrateInsecureDeserialization();

            _logger.LogInformation("DevSecOps08 page load completed");
        }

        // VULNERABILITY: SQL Injection and hardcoded credentials
        private void DemonstrateInsecureDatabaseConnection()
        {
            try
            {
                _logger.LogInformation("Attempting database connection with hardcoded credentials...");
                
                using var connection = new SqlConnection(DB_CONNECTION);
                
                // VULNERABILITY: SQL Injection - constructing query with string concatenation
                string userId = Request.Query.ContainsKey("userId") ? Request.Query["userId"].ToString() ?? "1" : "1";
                string query = "SELECT * FROM Users WHERE UserId = " + userId; // SQL Injection vulnerability
                
                // Log forging in SQL context
                _logger.LogInformation($"Executing query: {query}");
                
                // Don't actually execute for demo purposes, but this is the pattern
                // using var command = new SqlCommand(query, connection);
                // connection.Open();
                // var reader = command.ExecuteReader();
                
                _logger.LogInformation("Database connection demonstration completed (not actually executed)");
            }
            catch (Exception ex)
            {
                // VULNERABILITY: Logging potentially sensitive exception details
                _logger.LogError($"Database operation failed: {ex.ToString()}");
                _logger.LogError($"Connection string used: {DB_CONNECTION}");
            }
        }

        // VULNERABILITY: ReDoS (Regular Expression Denial of Service)
        private void DemonstrateRegexVulnerability()
        {
            try
            {
                string testInput = Request.Query.ContainsKey("regex") ? Request.Query["regex"].ToString() ?? "aaa" : "aaa";
                
                // Log forging with user input
                _logger.LogInformation($"Testing regex pattern with input: {testInput}");
                
                // VULNERABILITY: This regex can cause exponential backtracking
                bool match = VulnerablePattern.IsMatch(testInput);
                
                _logger.LogInformation($"Regex match result: {match} for pattern: {testInput}");
                
                // Another vulnerable regex pattern
                string email = Request.Query.ContainsKey("email") ? Request.Query["email"].ToString() ?? "" : "";
                if (!string.IsNullOrEmpty(email))
                {
                    bool emailValid = InsecureEmailRegex.IsMatch(email);
                    _logger.LogInformation($"Email validation for {email}: {emailValid}");
                }
            }
            catch (Exception ex)
            {
                // Log forging in exception handling
                _logger.LogError($"Regex evaluation error: {ex.Message} for user input");
            }
        }

        // VULNERABILITY: Insecure Deserialization
        private void DemonstrateInsecureDeserialization()
        {
            try
            {
                _logger.LogInformation("Demonstrating JSON deserialization...");
                
                // Get JSON from query parameter
                string jsonInput = Request.Query.ContainsKey("json") ? Request.Query["json"].ToString() ?? "{}" : "{}";
                
                // VULNERABILITY: Log forging with untrusted JSON input
                _logger.LogInformation($"Deserializing JSON: {jsonInput}");
                
                // VULNERABILITY: Deserializing untrusted JSON without type validation
                var settings = new JsonSerializerSettings
                {
                    TypeNameHandling = TypeNameHandling.All // This is dangerous!
                };
                
                // This could lead to remote code execution if attacker controls the JSON
                var deserializedObject = JsonConvert.DeserializeObject(jsonInput, settings);
                
                _logger.LogInformation($"Deserialization completed successfully");
            }
            catch (Exception ex)
            {
                // Logging full exception which may contain sensitive data
                _logger.LogError($"Deserialization failed with exception: {ex}");
            }
        }

        // VULNERABILITY: Command Injection potential
        public IActionResult OnPostExecuteCommand(string command)
        {
            try
            {
                // VULNERABILITY: Log forging - unsanitized command in logs
                _logger.LogInformation($"Executing system command: {command}");
                
                if (string.IsNullOrEmpty(command))
                {
                    _logger.LogWarning("Empty command received");
                    return BadRequest("Command cannot be empty");
                }

                // VULNERABILITY: Potential command injection if this were actually executed
                // In a real vulnerable scenario, this would execute arbitrary commands
                // System.Diagnostics.Process.Start("cmd.exe", $"/c {command}");
                
                _logger.LogInformation($"Command execution simulated for: {command}");
                
                TempData["CommandResult"] = $"Command '{command}' would be executed (simulation only)";
                return RedirectToPage();
            }
            catch (Exception ex)
            {
                // VULNERABILITY: Exposing sensitive error details
                _logger.LogError($"Command execution failed: {ex.ToString()}");
                TempData["CommandError"] = $"Error: {ex.Message}";
                return RedirectToPage();
            }
        }

        // VULNERABILITY: Path Traversal
        public IActionResult OnGetDownloadFile(string fileName)
        {
            try
            {
                // VULNERABILITY: Log forging with file name
                _logger.LogInformation($"File download requested: {fileName}");
                
                if (string.IsNullOrEmpty(fileName))
                {
                    _logger.LogWarning("Empty filename provided");
                    return BadRequest("Filename cannot be empty");
                }

                // VULNERABILITY: Path traversal - no validation of fileName
                // Attacker could request "../../../../etc/passwd"
                string filePath = Path.Combine("uploads", fileName);
                
                _logger.LogInformation($"Attempting to access file at: {filePath}");
                
                // Don't actually read file for demo
                // return File(System.IO.File.ReadAllBytes(filePath), "application/octet-stream", fileName);
                
                return Content($"File download simulated for: {filePath}");
            }
            catch (Exception ex)
            {
                // VULNERABILITY: Detailed error exposure
                _logger.LogError($"File download error for '{fileName}': {ex.ToString()}");
                return StatusCode(500, $"Error: {ex.Message}");
            }
        }

        // VULNERABILITY: Weak cryptographic random
        private string GenerateSessionToken()
        {
            // VULNERABILITY: Using non-cryptographic random for security tokens
            Random random = new Random();
            byte[] tokenBytes = new byte[32];
            random.NextBytes(tokenBytes);
            
            string token = Convert.ToBase64String(tokenBytes);
            
            // Log forging with generated token
            _logger.LogInformation($"Generated session token: {token}");
            
            return token;
        }

        // VULNERABILITY: Hardcoded secrets in code
        private void AuthenticateWithAPI()
        {
            try
            {
                _logger.LogInformation("Authenticating with external API...");
                
                // VULNERABILITY: Hardcoded API key
                _logger.LogDebug($"Using API key: {API_KEY}");
                
                // VULNERABILITY: Sensitive data in logs
                _logger.LogInformation($"API authentication with key: {API_KEY.Substring(0, 10)}...");
            }
            catch (Exception ex)
            {
                _logger.LogError($"API authentication failed: {ex}");
            }
        }
    }
}
