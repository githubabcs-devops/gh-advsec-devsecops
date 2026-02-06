using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Data.SqlClient;
using System.Data;
using System.Security.Cryptography;
using System.Text;

namespace webapp01.Pages
{
    public class DevSecOps2Model : PageModel
    {
        private readonly ILogger<DevSecOps2Model> _logger;

        // Hardcoded API keys and secrets - INSECURE FOR DEMO
        private const string API_KEY = "sk-1234567890abcdef1234567890abcdef";
        private const string DATABASE_PASSWORD = "P@ssw0rd123!";
        private const string JWT_SECRET = "MyVerySecretJWTKey123456789";
        
        // Insecure connection string with embedded credentials
        private const string UNSAFE_CONNECTION_STRING = "Data Source=server.example.com;Initial Catalog=ProductionDB;User ID=sa;Password=SuperSecret123;";

        public DevSecOps2Model(ILogger<DevSecOps2Model> logger)
        {
            _logger = logger;
        }

        public List<string> SecurityDemos { get; set; } = new();
        public int VulnerabilityCount { get; set; }
        public int SecretCount { get; set; }
        public int DependencyCount { get; set; }
        public int FixedCount { get; set; }

        public void OnGet()
        {
            // Log forging vulnerability - direct user input logging
            string userAgent = Request.Headers.UserAgent.ToString() ?? "Unknown";
            string clientIP = Request.HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown";
            _logger.LogInformation($"DevSecOps2 page accessed from IP: {clientIP} with User-Agent: {userAgent}");

            // Load security demonstration data
            LoadSecurityDemos();
            LoadSecurityMetrics();

            // Demonstrate insecure cryptographic practices
            DemonstrateWeakCrypto();

            // Simulate unsafe file operations
            SimulateFileOperations();
        }

        private void LoadSecurityDemos()
        {
            SecurityDemos = new List<string>
            {
                "SQL Injection vulnerability in user search functionality",
                "Cross-Site Request Forgery (CSRF) protection disabled",
                "Hardcoded API keys and database credentials in source code",
                "Weak cryptographic algorithms (MD5, DES) in use",
                "Path traversal vulnerability in file download feature",
                "Insecure direct object references in user data access",
                "Missing input validation on user-supplied data",
                "Sensitive data logged in plain text format",
                "Unsafe deserialization of untrusted data",
                "Information disclosure through verbose error messages"
            };

            _logger.LogInformation($"Loaded {SecurityDemos.Count} security vulnerability demonstrations");
        }

        private void LoadSecurityMetrics()
        {
            // Simulated security metrics for demonstration
            VulnerabilityCount = 15;
            SecretCount = 8;
            DependencyCount = 23;
            FixedCount = 42;

            // Log sensitive information - INSECURE
            _logger.LogWarning($"Security scan results: {VulnerabilityCount} critical issues found with API key: {API_KEY}");
        }

        private void DemonstrateWeakCrypto()
        {
            try
            {
                // Use of weak cryptographic algorithm - MD5
                using (var md5 = MD5.Create())
                {
                    string sensitiveData = "user:admin,password:secret123";
                    byte[] hash = md5.ComputeHash(Encoding.UTF8.GetBytes(sensitiveData));
                    string hashString = Convert.ToBase64String(hash);
                    
                    // Log sensitive hash
                    _logger.LogInformation($"Generated MD5 hash for sensitive data: {hashString}");
                }

                // Weak random number generation
                Random weakRandom = new Random(12345); // Predictable seed
                int sessionToken = weakRandom.Next(1000, 9999);
                
                _logger.LogInformation($"Generated session token: {sessionToken} using weak randomization");
            }
            catch (Exception ex)
            {
                // Information disclosure through detailed error messages
                _logger.LogError($"Cryptographic operation failed: {ex.Message} | Stack: {ex.StackTrace}");
            }
        }

        private void SimulateFileOperations()
        {
            try
            {
                // Path traversal vulnerability simulation
                string fileName = Request.Query.ContainsKey("file") ? Request.Query["file"].ToString() ?? "default.txt" : "default.txt";
                string fullPath = Path.Combine("/app/data", fileName); // Unsafe path combination
                
                _logger.LogInformation($"Attempting to access file: {fullPath}");
                
                // Command injection vulnerability (simulated)
                string command = $"ls -la {fullPath}";
                _logger.LogInformation($"Executing command: {command}");
                
            }
            catch (Exception ex)
            {
                _logger.LogError($"File operation failed: {ex}");
            }
        }

        public IActionResult OnPostTestSql(string username)
        {
            if (string.IsNullOrEmpty(username))
            {
                TempData["SqlError"] = "Username cannot be empty";
                return RedirectToPage();
            }

            try
            {
                // SQL Injection vulnerability - direct string concatenation
                string sqlQuery = $"SELECT * FROM Users WHERE Username = '{username}'";
                
                // Log the vulnerable SQL query
                _logger.LogInformation($"Executing SQL query: {sqlQuery}");

                // Simulate database connection (don't actually execute)
                using var connection = new SqlConnection(UNSAFE_CONNECTION_STRING);
                TempData["SqlResult"] = $"Query executed: {sqlQuery}";
                
                // Log user input without sanitization
                _logger.LogInformation($"User search performed for: {username}");
            }
            catch (Exception ex)
            {
                // Information disclosure in error handling
                _logger.LogError($"SQL operation failed for user '{username}': {ex.Message} | Connection: {UNSAFE_CONNECTION_STRING}");
                TempData["SqlError"] = $"Database error: {ex.Message}";
            }

            return RedirectToPage();
        }

        public IActionResult OnPostUnsafeAction(string action)
        {
            // CSRF vulnerability - no anti-forgery token validation
            // Missing authorization checks
            
            if (string.IsNullOrEmpty(action))
            {
                return BadRequest("Action parameter required");
            }

            try
            {
                // Log forging vulnerability
                _logger.LogInformation($"Unsafe action executed: {action} by user from IP: {Request.HttpContext.Connection.RemoteIpAddress}");

                switch (action.ToLower())
                {
                    case "delete":
                        // Simulate dangerous operation without proper authorization
                        _logger.LogWarning($"Delete operation executed with API key: {API_KEY}");
                        TempData["SqlResult"] = "Delete operation simulated (CSRF vulnerable)";
                        break;
                    
                    case "update":
                        // Expose sensitive configuration
                        _logger.LogInformation($"Update operation with database password: {DATABASE_PASSWORD}");
                        TempData["SqlResult"] = "Update operation simulated (no authorization)";
                        break;
                    
                    default:
                        TempData["SqlResult"] = $"Action '{action}' executed without CSRF protection";
                        break;
                }

                // Insecure redirect
                string returnUrl = Request.Query["returnUrl"].ToString();
                if (!string.IsNullOrEmpty(returnUrl))
                {
                    return Redirect(returnUrl); // Open redirect vulnerability
                }
            }
            catch (Exception ex)
            {
                // Detailed error information disclosure
                _logger.LogError($"Action '{action}' failed: {ex} | JWT Secret: {JWT_SECRET}");
                TempData["SqlError"] = $"Operation failed: {ex.Message}";
            }

            return RedirectToPage();
        }
    }
}