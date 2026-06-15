using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace CyberDetectionAI.Infrastructure.Services
{
    public class EmbeddingService : IEmbeddingService
    {
        private readonly HttpClient _httpClient;
        public EmbeddingService(HttpClient httpClient)
        {
            _httpClient = httpClient;
        }

        private string RemoveHtml(string html)
        {
            return Regex.Replace(
            html,
            "<.*?>",
            string.Empty);
        }

        public async Task<float[]>GenerateEmbeddingAsync(string text)
        {
            text = RemoveHtml(text);
            var request = new
            {
                model = "nomic-embed-text",
                prompt = text
            };

            var response =
                await _httpClient.PostAsJsonAsync(
                    "http://localhost:11434/api/embeddings",
                    request);

            response.EnsureSuccessStatusCode();

            JsonElement result =
    await response.Content
        .ReadFromJsonAsync<JsonElement>();

            return result
                .GetProperty("embedding")
                .Deserialize<float[]>()!;
        }

        public double CosineSimilarity(
        float[] a,
        float[] b)
        {
            double dot = 0;
            double magA = 0;
            double magB = 0;

            for (int i = 0; i < a.Length; i++)
            {
                dot += a[i] * b[i];

                magA += a[i] * a[i];

                magB += b[i] * b[i];
            }

            return dot /
                (Math.Sqrt(magA) * Math.Sqrt(magB));
        }
    }
}
