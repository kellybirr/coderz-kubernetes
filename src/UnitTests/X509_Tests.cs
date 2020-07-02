using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using Xunit;
using Xunit.Abstractions;

namespace UnitTests
{
    public class X509_Tests
    {
        private readonly string _basePath;
        private readonly ITestOutputHelper _out;

        public X509_Tests(ITestOutputHelper outputHelper)
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
            Assert.False(certificates[1].HasPrivateKey);

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
            Assert.False(certificates[1].HasPrivateKey);

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
            Assert.False(certificates[1].HasPrivateKey);

            _out.WriteLine(certificates[0].ToString());
        }

        [Theory]
        [InlineData("rsa")]
        [InlineData("ecdsa")]
        public void NoPrivateKey_Test(string alg)
        {
            // test setup
            string certPath = Path.Combine(_basePath, alg);
            string certString = File.ReadAllText(Path.Combine(certPath, "tls.crt"));

            // run test
            var certificates = new X509Certificate2Collection();
            X509Certificate2 privateKeyCert = certificates.ImportPemStrings(certString);

            Assert.Equal(2, certificates.Count);

            Assert.Null(privateKeyCert);

            Assert.False(certificates[0].HasPrivateKey);
            Assert.False(certificates[1].HasPrivateKey);
        }

        [Fact]
        public void Import_And_AddTrustStores_Test()
        {
            if (! RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                return; // run on linux only

            // test setup
            string certPath = Path.Combine(_basePath, "rsa");

            // run test
            var certificates = new X509Certificate2Collection();
            X509Certificate2 privateKeyCert = certificates.ImportTlsSecret(certPath);

            Assert.Equal(2, certificates.Count);

            certificates.AddToTrustStores(StoreLocation.CurrentUser);

            using (X509Store myCertStore = new X509Store(StoreName.My, StoreLocation.CurrentUser, OpenFlags.ReadOnly))
            {
                Assert.True(myCertStore.Certificates.Contains(privateKeyCert));
                Assert.False(myCertStore.Certificates.Contains(certificates[1]));
            }

            using (X509Store authCertStore = new X509Store(StoreName.CertificateAuthority, StoreLocation.CurrentUser, OpenFlags.ReadOnly))
            {
                Assert.False(authCertStore.Certificates.Contains(privateKeyCert));
                Assert.True(authCertStore.Certificates.Contains(certificates[1]));
            }

            using (X509Store rootCertStore = new X509Store(StoreName.Root, StoreLocation.CurrentUser, OpenFlags.ReadOnly))
            {
                Assert.False(rootCertStore.Certificates.Contains(privateKeyCert));
                Assert.False(rootCertStore.Certificates.Contains(certificates[1]));
            }
        }

        [Theory]
        [InlineData("ecdsa")]
        public void LoadCaSecret_Test(string alg)
        {
            // test setup
            string certPath = Path.Combine(_basePath, alg);

            // run test
            var certificates = new X509Certificate2Collection();
            certificates.ImportCaSecret(certPath);

            Assert.Equal(2, certificates.Count);

            Assert.False(certificates[0].HasPrivateKey);
            Assert.False(certificates[1].HasPrivateKey);
        }

    }
}
