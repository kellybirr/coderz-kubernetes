using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using Coderz.Kubernetes.Extensions;
using Xunit;

namespace UnitTests
{
    public class TlsSecret_Tests
    {
        [Theory]
        [InlineData("rsa")]
        [InlineData("ecdsa")]
        public void LoadFromPath_Test(string alg)
        {
            X509Certificate2Collection collection = TlsSecret.FromMappedPath("D:\\tls_kube_example\\"+alg);
            
            Assert.NotNull(collection);
            Assert.Equal(2, collection.Count);
            Assert.True(collection[0].HasPrivateKey);
        }

        [Theory]
        [InlineData("rsa")]
        [InlineData("ecdsa")]
        public void LoadFromStrings_Test(string alg)
        {
            // test setup
            string basePath = "D:\\tls_kube_example\\" + alg;
            string certString = File.ReadAllText(Path.Combine(basePath, "tls.crt"));
            string keyString = File.ReadAllText(Path.Combine(basePath, "tls.key"));

            // run test
            X509Certificate2Collection collection = TlsSecret.FromPemStrings(certString, keyString);

            Assert.NotNull(collection);
            Assert.Equal(2, collection.Count);
            Assert.True(collection[0].HasPrivateKey);
        }
        [Theory]
        [InlineData("rsa")]
        [InlineData("ecdsa")]
        public void LoadFromEnvironment_Test(string alg)
        {
            // test setup
            string basePath = "D:\\tls_kube_example\\" + alg;
            string certString = File.ReadAllText(Path.Combine(basePath, "tls.crt"));
            string keyString = File.ReadAllText(Path.Combine(basePath, "tls.key"));

            Environment.SetEnvironmentVariable("tls_crt", certString);
            Environment.SetEnvironmentVariable("tls_key", keyString);

            // run test
            X509Certificate2Collection collection = TlsSecret.FromEnvironment();

            Assert.NotNull(collection);
            Assert.Equal(2, collection.Count);
            Assert.True(collection[0].HasPrivateKey);
        }

    }
}
