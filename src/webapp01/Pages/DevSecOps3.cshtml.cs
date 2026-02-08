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

        public DevSecOps3Model(ILogger<DevSecOps3Model> logger)
        {
            _logger = logger;
        }

        public void OnGet()
        {
            _logger.LogInformation("DevSecOps3 page accessed at {DateTime}", DateTime.Now);
        }

        public IActionResult OnPostTestRegex(string userInput)
        {
            try
            {
                // SECURITY ISSUE: This regex pattern is vulnerable to ReDoS (Regular Expression Denial of Service)
                // The pattern (a+)+ creates exponential backtracking with inputs like "aaaaaaaaaaaaaaaaaaaaaaaaaaaa!"
                var vulnerablePattern = @"^(a+)+$";
                
                _logger.LogInformation("Testing regex with input: {Input}", userInput);
                
                var regex = new Regex(vulnerablePattern);
                var isMatch = regex.IsMatch(userInput ?? "");
                
                TempData["RegexResult"] = $"Regex test completed. Input '{userInput}' match result: {isMatch}";
                
                return RedirectToPage();
            }
            catch (Exception ex)
            {
                // SECURITY ISSUE: Exposing exception details in logs without sanitization
                _logger.LogError("Regex processing failed: {Exception}", ex.ToString());
                TempData["RegexError"] = $"Regex processing failed: {ex.Message}";
                return RedirectToPage();
            }
        }

        public IActionResult OnPostTestLogging(string logMessage)
        {
            try
            {
                // SECURITY ISSUE: Log forging vulnerability - user input directly written to logs
                // Malicious input like "Normal log\r\n[ADMIN] Unauthorized access granted" 
                // could inject fake log entries
                _logger.LogInformation("User action: {Message}", logMessage);
                
                // SECURITY ISSUE: Hardcoded credentials for demo purposes
                var connectionString = "Server=localhost;Database=TestDB;User Id=admin;Password=Password123!;";
                
                // SECURITY ISSUE: Potential SQL injection if this were used in actual queries
                var sqlQuery = $"INSERT INTO Logs (Message) VALUES ('{logMessage}')";
                
                // SECURITY ISSUE: Using both JSON libraries unnecessarily (dependency confusion risk)
                var jsonData = JsonConvert.SerializeObject(new { message = logMessage, timestamp = DateTime.Now });
                var systemJsonData = System.Text.Json.JsonSerializer.Serialize(new { message = logMessage, timestamp = DateTime.Now });
                
                _logger.LogInformation("Serialized data: {JsonData}", jsonData);
                
                TempData["LogResult"] = $"Log entry created: '{logMessage}' at {DateTime.Now}";
                
                return RedirectToPage();
            }
            catch (Exception ex)
            {
                // SECURITY ISSUE: Excessive error information disclosure
                _logger.LogError("Logging operation failed with full exception: {FullException}", ex);
                TempData["LogResult"] = $"Logging failed: {ex.Message} - {ex.StackTrace}";
                return RedirectToPage();
            }
        }

        // SECURITY ISSUE: Method with potential for misuse if exposed
        private void ProcessSensitiveData(string userData)
        {
            // SECURITY ISSUE: No input validation or sanitization
            var processedData = userData.ToUpper();
            
            // SECURITY ISSUE: Logging sensitive data without redaction
            _logger.LogInformation("Processing sensitive data: {SensitiveData}", processedData);
            
            // SECURITY ISSUE: Hardcoded secret key
            var secretKey = "MySecretKey123!@#";
            
            // SECURITY ISSUE: Weak encryption simulation
            var encodedData = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(processedData + secretKey));
            
            _logger.LogInformation("Encoded result: {EncodedData}", encodedData);
        }
    }
}
