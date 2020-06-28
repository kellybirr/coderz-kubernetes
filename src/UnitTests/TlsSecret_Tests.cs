using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using Coderz.Kubernetes.Extensions;
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
            string certPath = Path.Combine(_basePath, alg);
            X509Certificate2Collection collection = TlsSecret.FromMappedPath(certPath);
            
            Assert.NotNull(collection);
            Assert.Equal(2, collection.Count);
            Assert.True(collection[0].HasPrivateKey);

            _out.WriteLine(collection[0].ToString());
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
            X509Certificate2Collection collection = TlsSecret.FromPemStrings(certString, keyString);

            Assert.NotNull(collection);
            Assert.Equal(2, collection.Count);
            Assert.True(collection[0].HasPrivateKey); 
            
            _out.WriteLine(collection[0].ToString());
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
            X509Certificate2Collection collection = TlsSecret.FromEnvironment();

            Assert.NotNull(collection);
            Assert.Equal(2, collection.Count);
            Assert.True(collection[0].HasPrivateKey);

            _out.WriteLine(collection[0].ToString());
        }
    }
}
