using System.Net.Http;
using System.Threading.Tasks;
using Xunit;

namespace SafeVault.Tests
{
    public class SecurityTests
    {
        private readonly HttpClient _client;

        public SecurityTests()
        {
            // Assumes the app is running on localhost:5113
            _client = new HttpClient { BaseAddress = new System.Uri("http://localhost:5113") };
        }

        [Theory]
        [InlineData("testuser', DROP TABLE Users;--", "test@example.com")]
        [InlineData("admin", "test@example.com' OR '1'='1")]
        public async Task SqlInjection_Attempt_IsRejected(string username, string email)
        {
            var content = new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("username", username),
                new KeyValuePair<string, string>("email", email)
            });
            var response = await _client.PostAsync("/submit", content);
            var body = await response.Content.ReadAsStringAsync();
            Assert.False(body.Contains("syntax error", System.StringComparison.OrdinalIgnoreCase));
            Assert.DoesNotContain("DROP TABLE", body);
            Assert.True(response.IsSuccessStatusCode || response.StatusCode == System.Net.HttpStatusCode.BadRequest);
        }

        [Theory]
        [InlineData("<script>alert('xss')</script>", "xss@example.com")]
        [InlineData("xssuser", "<img src=x onerror=alert('xss')>")]
        public async Task XssInjection_Attempt_IsSanitized(string username, string email)
        {
            var content = new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("username", username),
                new KeyValuePair<string, string>("email", email)
            });
            var response = await _client.PostAsync("/submit", content);
            var body = await response.Content.ReadAsStringAsync();
            Assert.DoesNotContain("<script>", body, System.StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("onerror", body, System.StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("alert(", body, System.StringComparison.OrdinalIgnoreCase);
        }
    }
}
