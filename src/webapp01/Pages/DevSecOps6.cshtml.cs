using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Diagnostics;
using System.Text.Json;
using Newtonsoft.Json;

namespace webapp01.Pages
{
    public class DevSecOps6Model : PageModel
    {
        private readonly ILogger<DevSecOps6Model> _logger;

        // Hardcoded container registry credentials - SECURITY VULNERABILITY
        private const string CONTAINER_REGISTRY_URL = "registry.acme.com";
        private const string REGISTRY_USERNAME = "admin";
        private const string REGISTRY_PASSWORD = "DockerPass123!";
        
        // Hardcoded cloud provider credentials - SECURITY VULNERABILITY
        private const string AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE";
        private const string AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        private const string AZURE_TENANT_ID = "12345678-1234-1234-1234-123456789012";
        
        // Insecure container configuration - SECURITY VULNERABILITY
        private const string DOCKER_SOCKET_PATH = "/var/run/docker.sock";
        private const bool PRIVILEGED_CONTAINER = true;
        private const string CONTAINER_USER = "root";

        public DevSecOps6Model(ILogger<DevSecOps6Model> logger)
        {
            _logger = logger;
        }

        public List<string> ContainerSecurityFeatures { get; set; } = new();

        public void OnGet()
        {
            // Log forging vulnerability - unsanitized user input in logs
            string userAgent = Request.Headers.ContainsKey("User-Agent") 
                ? Request.Headers["User-Agent"].ToString() 
                : "Unknown";
            string requestPath = Request.Path.ToString();
            
            _logger.LogInformation($"DevSecOps6 page accessed by: {userAgent} at path: {requestPath}");

            // Environment variable exposure demonstration
            DemonstrateEnvironmentVariableExposure();

            // Load container security features with potential vulnerabilities
            LoadContainerSecurityFeatures();

            // Demonstrate insecure container operations
            DemonstrateContainerVulnerabilities();

            // Test cloud provider credential exposure
            DemonstrateCloudCredentialExposure();
        }

        private void DemonstrateEnvironmentVariableExposure()
        {
            try
            {
                // Environment variable exposure - logging sensitive information
                string dbPassword = Environment.GetEnvironmentVariable("DATABASE_PASSWORD") ?? "defaultpass123";
                string apiKey = Environment.GetEnvironmentVariable("API_KEY") ?? "sk-default-key";
                string jwtSecret = Environment.GetEnvironmentVariable("JWT_SECRET") ?? "super-secret-jwt-key";
                
                // VULNERABILITY: Logging sensitive environment variables
                _logger.LogDebug($"Environment check - DB Password: {dbPassword}, API Key: {apiKey}, JWT Secret: {jwtSecret}");
                
                // VULNERABILITY: Exposing all environment variables
                foreach (var envVar in Environment.GetEnvironmentVariables().Cast<System.Collections.DictionaryEntry>())
                {
                    _logger.LogTrace($"Environment variable found: {envVar.Key} = {envVar.Value}");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Environment variable demo failed: {ex.Message}");
            }
        }

        private void LoadContainerSecurityFeatures()
        {
            ContainerSecurityFeatures = new List<string>
            {
                "Container image scanning with SBOM generation and vulnerability correlation analysis",
                "Runtime container behavior monitoring with ML-based anomaly detection",
                "Kubernetes security policies with admission controller integration and RBAC enforcement",
                "Container registry security with image signing, verification, and notary service integration",
                "Supply chain security with provenance tracking, attestation, and SLSA compliance verification",
                "Infrastructure-as-Code security scanning for Terraform, ARM templates, and CloudFormation",
                "Cloud workload protection with runtime threat detection and automated incident response",
                "Container network security with service mesh integration and zero-trust networking",
                "Secrets management integration with HashiCorp Vault, Azure Key Vault, and AWS Secrets Manager",
                "Compliance automation with SOC2, PCI-DSS, HIPAA, and custom framework support"
            };

            try
            {
                // Unsafe deserialization vulnerability
                string jsonData = JsonConvert.SerializeObject(ContainerSecurityFeatures);
                
                // VULNERABILITY: Unsafe JSON deserialization settings
                var settings = new JsonSerializerSettings
                {
                    TypeNameHandling = TypeNameHandling.Auto, // Enables type confusion attacks
                    DefaultValueHandling = DefaultValueHandling.Include
                };
                
                var deserializedFeatures = JsonConvert.DeserializeObject<List<string>>(jsonData, settings);
                
                _logger.LogInformation($"Loaded {ContainerSecurityFeatures.Count} container security features via unsafe deserialization");
            }
            catch (Exception ex)
            {
                // Information disclosure through detailed error messages
                _logger.LogError($"Container features loading failed: {ex.Message} | Stack: {ex.StackTrace}");
            }
        }

        private void DemonstrateContainerVulnerabilities()
        {
            try
            {
                // VULNERABILITY: Container privilege escalation
                _logger.LogWarning($"Container running with privileged mode: {PRIVILEGED_CONTAINER}");
                _logger.LogWarning($"Container user: {CONTAINER_USER}");
                _logger.LogWarning($"Docker socket access: {DOCKER_SOCKET_PATH}");
                
                // VULNERABILITY: Hardcoded container registry credentials
                _logger.LogDebug($"Container registry: {CONTAINER_REGISTRY_URL} with user: {REGISTRY_USERNAME} and password: {REGISTRY_PASSWORD}");
                
                // Simulate container command execution vulnerability
                string containerCommand = Request.Query.ContainsKey("cmd") 
                    ? Request.Query["cmd"].ToString() ?? "" 
                    : "";
                    
                if (!string.IsNullOrEmpty(containerCommand))
                {
                    // VULNERABILITY: Command injection through user input
                    _logger.LogWarning($"Attempting to execute container command: {containerCommand}");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Container vulnerability demo failed: {ex.Message}");
            }
        }

        private void DemonstrateCloudCredentialExposure()
        {
            try
            {
                // VULNERABILITY: Cloud provider credential exposure
                _logger.LogDebug($"AWS Access Key: {AWS_ACCESS_KEY}");
                _logger.LogDebug($"AWS Secret Key: {AWS_SECRET_KEY.Substring(0, 10)}...");
                _logger.LogDebug($"Azure Tenant ID: {AZURE_TENANT_ID}");
                
                // VULNERABILITY: Insecure cloud resource access patterns
                string cloudResource = $"https://storage.blob.core.windows.net/container?key={AWS_SECRET_KEY}";
                _logger.LogInformation($"Cloud resource URL generated: {cloudResource}");
                
                // VULNERABILITY: Insecure temporary file creation
                string tempFile = Path.Combine(Path.GetTempPath(), "cloud-credentials.txt");
                System.IO.File.WriteAllText(tempFile, $"AWS_KEY={AWS_ACCESS_KEY}\nAWS_SECRET={AWS_SECRET_KEY}");
                _logger.LogDebug($"Temporary credentials file created: {tempFile}");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Cloud credential demo failed: {ex.Message}");
            }
        }

        public IActionResult OnPostTestEnvironmentVariables(string envVar, string envValue)
        {
            try
            {
                if (string.IsNullOrEmpty(envVar) || string.IsNullOrEmpty(envValue))
                {
                    TempData["SecurityDemoError"] = "Both environment variable name and value are required.";
                    return Page();
                }

                // Log forging vulnerability - direct user input in logs
                _logger.LogInformation($"Environment variable test initiated: {envVar} = {envValue}");

                // VULNERABILITY: Environment variable injection
                Environment.SetEnvironmentVariable(envVar, envValue);
                
                // VULNERABILITY: Unsafe environment variable access
                string retrievedValue = Environment.GetEnvironmentVariable(envVar);
                
                string result = $"Environment variable '{envVar}' set to '{envValue}' and retrieved as '{retrievedValue}'";
                
                // Information disclosure vulnerability
                _logger.LogInformation($"Environment test result: {result}");
                TempData["SecurityDemoResult"] = result;

                // Additional vulnerability - exposing system environment
                var systemEnvVars = Environment.GetEnvironmentVariables();
                _logger.LogDebug($"Total system environment variables: {systemEnvVars.Count}");
            }
            catch (Exception ex)
            {
                // Information disclosure through error messages
                string errorMsg = $"Environment variable test failed: {ex.Message} | Type: {ex.GetType().Name}";
                _logger.LogError(errorMsg);
                TempData["SecurityDemoError"] = errorMsg;
            }

            return Page();
        }

        public IActionResult OnPostTestContainerCommand(string command)
        {
            try
            {
                if (string.IsNullOrEmpty(command))
                {
                    TempData["SecurityDemoError"] = "Container command is required for demonstration.";
                    return Page();
                }

                // Log forging vulnerability - unsanitized user input
                _logger.LogInformation($"Container command test initiated: {command}");

                // VULNERABILITY: Command injection - executing user input without sanitization
                var processInfo = new ProcessStartInfo
                {
                    FileName = "/bin/bash",
                    Arguments = $"-c \"{command}\"", // Direct command injection vulnerability
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                // VULNERABILITY: Unsafe process execution
                _logger.LogDebug($"Executing container command via process: {processInfo.FileName} {processInfo.Arguments}");
                
                string result = $"Container command '{command}' scheduled for execution";
                TempData["SecurityDemoResult"] = result;
                
                // Additional vulnerability - exposing container runtime information
                _logger.LogInformation($"Container runtime: {Environment.OSVersion} | User: {Environment.UserName}");
                _logger.LogWarning($"Container privileges: Running as {(Environment.UserName == "root" ? "ROOT" : "NON-ROOT")}");
            }
            catch (Exception ex)
            {
                // Information disclosure through detailed error messages
                string errorMsg = $"Container command test failed: {ex.Message} | Stack: {ex.StackTrace?.Substring(0, Math.Min(200, ex.StackTrace?.Length ?? 0))}";
                _logger.LogError(errorMsg);
                TempData["SecurityDemoError"] = errorMsg;
            }

            return Page();
        }
    }
}