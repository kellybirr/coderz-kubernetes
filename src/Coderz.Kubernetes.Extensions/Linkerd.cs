// Ignore Spelling: Linkerd

using System;
using System.Net.Http;
using System.Threading.Tasks;

namespace Coderz.Kubernetes.Extensions
{
    public static class Linkerd
    {
        private static readonly HttpClient _http = new HttpClient { Timeout = TimeSpan.FromSeconds(2) };
        private const string _linkerdUrl = "http://localhost:4191/shutdown";

        public static bool TryShutdown() => TryShutdownAsync().Result;

        public static async Task<bool> TryShutdownAsync()
        {
            if (string.IsNullOrEmpty(Environment.GetEnvironmentVariable("KUBERNETES_PORT")))
                return false;

            try
            {
                HttpResponseMessage res = await _http.PostAsync(_linkerdUrl, null);
                return res.IsSuccessStatusCode;
            }
            catch
            {
                return false;
            }
        }
    }
}
