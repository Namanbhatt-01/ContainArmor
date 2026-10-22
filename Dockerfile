FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
WORKDIR /source

# Copy solution and project files
COPY ContainArmor.sln .
COPY src/ContainArmor.Engine/ContainArmor.Engine.csproj src/ContainArmor.Engine/
COPY src/ContainArmor.Api/ContainArmor.Api.csproj src/ContainArmor.Api/
COPY src/ContainArmor.Blazor/ContainArmor.Blazor.csproj src/ContainArmor.Blazor/

RUN dotnet restore ContainArmor.sln

# Copy source and publish
COPY . .
RUN dotnet publish src/ContainArmor.Blazor/ContainArmor.Blazor.csproj -c Release -o /app/publish

FROM mcr.microsoft.com/dotnet/aspnet:9.0 AS final
WORKDIR /app
COPY --from=build /app/publish .

# Install iptables tools for Linux netfilter auditing
RUN apt-get update && apt-get install -y --no-install-recommends iptables iproute2 curl && rm -rf /var/lib/apt/lists/*

ENV ASPNETCORE_URLS=http://+:5200
EXPOSE 5200

ENTRYPOINT ["dotnet", "ContainArmor.Blazor.dll"]
