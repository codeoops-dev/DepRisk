namespace DepRisk.Data.Tests;

/// <summary>
/// A real project.assets.json produced by 'dotnet restore' for a tiny app, trimmed to the parts DepRisk reads.
/// App references Demo.Lib.A 1.2.0 and Demo.Lib.D 3.0.0 directly.
/// Demo.Lib.A depends on Demo.Lib.B [1.0.0, 2.0.0) and Demo.Lib.C 2.1.0; Demo.Lib.B depends on Demo.Lib.C 2.0.0.
/// </summary>
internal static class Fixtures
{
    public const string SimpleApp = """
{
  "version": 3,
  "targets": {
    "net10.0": {
      "Demo.Lib.A/1.2.0": {
        "type": "package",
        "dependencies": {
          "Demo.Lib.B": "[1.0.0, 2.0.0)",
          "Demo.Lib.C": "2.1.0"
        }
      },
      "Demo.Lib.B/1.5.0": {
        "type": "package",
        "dependencies": {
          "Demo.Lib.C": "2.0.0"
        }
      },
      "Demo.Lib.C/2.1.0": {
        "type": "package"
      },
      "Demo.Lib.D/3.0.0": {
        "type": "package"
      }
    }
  },
  "libraries": {
    "Demo.Lib.A/1.2.0": {
      "type": "package",
      "path": "demo.lib.a/1.2.0"
    },
    "Demo.Lib.B/1.5.0": {
      "type": "package",
      "path": "demo.lib.b/1.5.0"
    },
    "Demo.Lib.C/2.1.0": {
      "type": "package",
      "path": "demo.lib.c/2.1.0"
    },
    "Demo.Lib.D/3.0.0": {
      "type": "package",
      "path": "demo.lib.d/3.0.0"
    }
  },
  "projectFileDependencyGroups": {
    "net10.0": [
      "Demo.Lib.A >= 1.2.0",
      "Demo.Lib.D >= 3.0.0"
    ]
  },
  "project": {
    "restore": {
      "projectName": "App",
      "projectStyle": "PackageReference"
    }
  }
}
""";
}
