using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;

internal static class TraceProcessorModules
{
    internal static SortedSet<string> Loaded(string toolkit, IEnumerable<Assembly> assemblies)
    {
        var names = new SortedSet<string>(StringComparer.Ordinal);
        foreach (var assembly in assemblies)
        {
            var name = assembly.GetName().Name + ".dll";
            var expected = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, name);
            if (!String.Equals(assembly.Location, expected, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException("Unexpected managed assembly location");
            }
            names.Add(name);
        }
        using (var process = Process.GetCurrentProcess())
        {
            foreach (ProcessModule module in process.Modules)
            {
                string name = module.ModuleName.ToLowerInvariant();
                if (name == "perfcore.dll" || name == "perfg.dll" || name.StartsWith("perf_", StringComparison.Ordinal))
                {
                    if (!String.Equals(module.FileName, Path.Combine(toolkit, name), StringComparison.OrdinalIgnoreCase))
                    {
                        throw new InvalidDataException("Unexpected toolkit module location");
                    }
                    names.Add("wpt/" + name);
                }
            }
        }
        if (!names.Contains("wpt/perfcore.dll"))
        {
            throw new InvalidDataException("Toolkit core unavailable");
        }
        return names;
    }
}
