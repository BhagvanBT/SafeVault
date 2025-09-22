public static class InputSanitizer
{
    // Remove potentially dangerous characters and scripts
    public static string Sanitize(string input)
    {
        if (string.IsNullOrEmpty(input)) return string.Empty;
        // Remove script tags and encode HTML
        string sanitized = System.Text.RegularExpressions.Regex.Replace(input, "<.*?>", string.Empty);
        sanitized = System.Net.WebUtility.HtmlEncode(sanitized);
        // Remove SQL special characters
        sanitized = sanitized.Replace("'", string.Empty).Replace("\"", string.Empty).Replace(";", string.Empty).Replace("--", string.Empty);
        return sanitized.Trim();
    }
}
