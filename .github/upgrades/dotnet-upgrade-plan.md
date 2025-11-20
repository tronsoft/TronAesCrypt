# .NET 10.0 Upgrade Plan

## Execution Steps

Execute steps below sequentially one by one in the order they are listed.

1. Validate that an .NET 10.0 SDK required for this upgrade is installed on the machine and if not, help to get it installed.
2. Ensure that the SDK version specified in global.json files is compatible with the .NET 10.0 upgrade.
3. Upgrade TronAesCrypt.Main/TronAesCrypt.Main.csproj
4. Upgrade TronAesCrypt.Main.Tests/TronAesCrypt.Main.Tests.csproj
5. Upgrade TronAesCrypt.Core.Tests/TronAesCrypt.Core.Tests.csproj

## Settings

This section contains settings and data used by execution steps.

### Excluded projects

Table below contains projects that do belong to the dependency graph for selected projects and should not be included in the upgrade.

| Project name                                   | Description                 |
|:-----------------------------------------------|:---------------------------:|

### Aggregate NuGet packages modifications across all projects

No NuGet package updates were suggested by the analysis.

### Project upgrade details
This section contains details about each project upgrade and modifications that need to be done in the project.

#### TronAesCrypt.Main/TronAesCrypt.Main.csproj modifications

Project properties changes:
  - Target framework should be changed from `net6.0` to `net10.0`

NuGet packages changes:
  - No specific NuGet package updates were suggested by the analysis for this project.

Other changes:
  - Review code for any API breaking changes introduced between .NET 6 and .NET 10 and address them as needed.

#### TronAesCrypt.Main.Tests/TronAesCrypt.Main.Tests.csproj modifications

Project properties changes:
  - Target framework should be changed from `net6.0` to `net10.0`

NuGet packages changes:
  - No specific NuGet package updates were suggested by the analysis for this test project.

Other changes:
  - Update test SDK packages if necessary and run tests after upgrade.

#### TronAesCrypt.Core.Tests/TronAesCrypt.Core.Tests.csproj modifications

Project properties changes:
  - Target framework should be changed from `net6.0` to `net10.0`

NuGet packages changes:
  - No specific NuGet package updates were suggested by the analysis for this test project.

Other changes:
  - Update test SDK packages if necessary and run tests after upgrade.

