using System.Net.Http;
using System.Threading.Tasks;
using Xunit;
using System.Collections.Generic;

namespace SafeVault.Tests
{
    public class AccessControlTests
    {
        private readonly HttpClient _client;

        public AccessControlTests()
        {
            // Assumes the app is running on localhost:5113
            _client = new HttpClient { BaseAddress = new System.Uri("http://localhost:5113") };
        }

        [Fact]
        public async Task InvalidLogin_IsRejected()
        {
            var content = new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("username", "nonexistentuser"),
                new KeyValuePair<string, string>("password", "wrongpassword")
            });
            var response = await _client.PostAsync("/login", content);
            Assert.Equal(System.Net.HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task User_CannotAccess_AdminDashboard()
        {
            // Register as normal user
            var regContent = new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("username", "user1"),
                new KeyValuePair<string, string>("email", "user1@example.com"),
                new KeyValuePair<string, string>("password", "userpass"),
                new KeyValuePair<string, string>("role", "user")
            });
            await _client.PostAsync("/register", regContent);

            // Login as user
            var loginContent = new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("username", "user1"),
                new KeyValuePair<string, string>("password", "userpass")
            });
            var loginResp = await _client.PostAsync("/login", loginContent);
            var cookies = loginResp.Headers.Contains("Set-Cookie") ? loginResp.Headers.GetValues("Set-Cookie") : null;
            var req = new HttpRequestMessage(HttpMethod.Get, "/admin");
            if (cookies != null)
                req.Headers.Add("Cookie", string.Join("; ", cookies));
            var adminResp = await _client.SendAsync(req);
            Assert.Equal(System.Net.HttpStatusCode.Forbidden, adminResp.StatusCode);
        }

        [Fact]
        public async Task Admin_CanAccess_AdminDashboard()
        {
            // Register as admin
            var regContent = new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("username", "admin1"),
                new KeyValuePair<string, string>("email", "admin1@example.com"),
                new KeyValuePair<string, string>("password", "adminpass"),
                new KeyValuePair<string, string>("role", "admin")
            });
            await _client.PostAsync("/register", regContent);

            // Login as admin
            var loginContent = new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("username", "admin1"),
                new KeyValuePair<string, string>("password", "adminpass")
            });
            var loginResp = await _client.PostAsync("/login", loginContent);
            var cookies = loginResp.Headers.Contains("Set-Cookie") ? loginResp.Headers.GetValues("Set-Cookie") : null;
            var req = new HttpRequestMessage(HttpMethod.Get, "/admin");
            if (cookies != null)
                req.Headers.Add("Cookie", string.Join("; ", cookies));
            var adminResp = await _client.SendAsync(req);
            Assert.Equal(System.Net.HttpStatusCode.OK, adminResp.StatusCode);
        }
    }
}
