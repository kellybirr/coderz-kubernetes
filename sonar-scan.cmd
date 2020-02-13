dotnet sonarscanner begin /k:"kellybirr_coderz-kubernetes" /o:"kellybirr" /d:sonar.host.url="https://sonarcloud.io" /d:sonar.login="d4130955c475f284619a69d8d7a1512d95043213"
dotnet build "Coderz.Kubernetes.Extensions.sln"
dotnet sonarscanner end /d:sonar.login="d4130955c475f284619a69d8d7a1512d95043213" 
