using System.IO;

// ReSharper disable once CheckNamespace
namespace Microsoft.Extensions.Configuration
{
    public static class KubernetesConfigMapExtensions
    {
        public static IConfigurationBuilder AddConfigMapJsonFiles(this IConfigurationBuilder builder)
        {
            string fsRoot = Directory.GetDirectoryRoot(Directory.GetCurrentDirectory());
            string configRoot = Path.Combine(fsRoot, "configmaps");

            return AddConfigMapJsonFiles(builder, configRoot);
        }

        public static IConfigurationBuilder AddConfigMapJsonFiles(this IConfigurationBuilder builder, string configRootPath)
        {
            if (Directory.Exists(configRootPath))
            {
                var configRootDir = new DirectoryInfo(configRootPath);
                foreach (DirectoryInfo configDir in configRootDir.GetDirectories())
                {
                    foreach (FileInfo configFile in configDir.GetFiles("*.json"))
                    {
                        builder.AddJsonFile(configFile.FullName, optional: false, reloadOnChange: true);
                    }
                }
            }

            return builder;
        }
    }
}
