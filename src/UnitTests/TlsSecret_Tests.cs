using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using Xunit;
using Xunit.Abstractions;

namespace UnitTests
{
    public class TlsSecret_Tests
    {
        private readonly string _basePath;
        private readonly ITestOutputHelper _out;

        public TlsSecret_Tests(ITestOutputHelper outputHelper)
        {
            _out = outputHelper;

            _basePath = (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                ? "D:\\tls_kube_example"
                : "/mnt/d/tls_kube_example";
        }

        [Theory]
        [InlineData("rsa")]
        [InlineData("ecdsa")]
        public void LoadFromPath_Test(string alg)
        {
            // test setup
            string certPath = Path.Combine(_basePath, alg);

            // run test
            var certificates = new X509Certificate2Collection();
            X509Certificate2 privateKeyCert = certificates.ImportTlsSecret(certPath);

            Assert.Equal(2, certificates.Count);

            Assert.NotNull(privateKeyCert);
            Assert.True(privateKeyCert.HasPrivateKey);

            Assert.Equal(privateKeyCert, certificates[0]);

            _out.WriteLine(privateKeyCert.ToString());
        }

        [Theory]
        [InlineData("rsa")]
        [InlineData("ecdsa")]
        public void LoadFromStrings_Test(string alg)
        {
            // test setup
            string certPath = Path.Combine(_basePath, alg);
            string certString = File.ReadAllText(Path.Combine(certPath, "tls.crt"));
            string keyString = File.ReadAllText(Path.Combine(certPath, "tls.key"));

            // run test
            var certificates = new X509Certificate2Collection();
            X509Certificate2 privateKeyCert = certificates.ImportPemStrings(certString, keyString);

            Assert.Equal(2, certificates.Count);

            Assert.NotNull(privateKeyCert);
            Assert.True(privateKeyCert.HasPrivateKey); 

            Assert.Equal(privateKeyCert, certificates[0]);

            _out.WriteLine(privateKeyCert.ToString());
        }

        [Theory]
        [InlineData("rsa")]
        [InlineData("ecdsa")]
        public void LoadFromEnvironment_Test(string alg)
        {
            // test setup
            string certPath = Path.Combine(_basePath, alg);
            string certString = File.ReadAllText(Path.Combine(certPath, "tls.crt"));
            string keyString = File.ReadAllText(Path.Combine(certPath, "tls.key"));

            Environment.SetEnvironmentVariable("tls_crt", certString);
            Environment.SetEnvironmentVariable("tls_key", keyString);

            // run test
            var certificates = new X509Certificate2Collection();
            X509Certificate2 privateKeyCert = certificates.ImportFromEnvironment();

            Assert.Equal(2, certificates.Count);

            Assert.NotNull(privateKeyCert);
            Assert.True(privateKeyCert.HasPrivateKey); 

            Assert.Equal(privateKeyCert, certificates[0]);

            _out.WriteLine(certificates[0].ToString());
        }
    }
}
