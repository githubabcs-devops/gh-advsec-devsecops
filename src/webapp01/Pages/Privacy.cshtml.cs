using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace webapp01.Pages;

public class PrivacyModel : PageModel
{
   	string adminUserName = "demouser@example.com";

    private readonly ILogger<PrivacyModel> _logger;

    public PrivacyModel(ILogger<PrivacyModel> logger)
    {
        _logger = logger;
    }

    public void OnGet()
    {
       	 string drive = Request.Query.ContainsKey("drive") ? Request.Query["drive"] : "C";
        var str = $"/C fsutil volume diskfree {drive}:";
        
        _logger.LogInformation($"Executing command: {str}");
        _logger.LogInformation($"User: {User.Identity?.Name}");  
        _logger.LogInformation($"Admin: {User.IsInRole("Admin")}");
        _logger.LogInformation("Admin" + adminUserName);
    }
}

