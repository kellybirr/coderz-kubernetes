FROM mcr.microsoft.com/dotnet/core/sdk:3.1-buster

WORKDIR /src

COPY . .
RUN dotnet build "src/UnitTests/UnitTests.csproj"

ENTRYPOINT ["dotnet", "test"]