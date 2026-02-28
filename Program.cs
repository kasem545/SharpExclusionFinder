using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

class Program
{
    static HashSet<string> excludedDirectories = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    static readonly HashSet<string> suppressedAccessDeniedDirectories = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
  {
    @"d:\\Config.Msi".TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar),
    @"d:\\Recovery".TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar),
    @"d:\\System Volume Information".TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
  };

    // Counter for progress
    static int counter = 0;

    static int totalDirectories = 0;

    static int maxThreads = 3;

    static int maxDepth = int.MaxValue; // By default, scan all depths

    // Stopwatch to measure performance
    static Stopwatch stopwatch = new Stopwatch();

    static string outputFile = null;

    static bool verbose = false;

    static string scanMethod = "bruteforce"; // bruteforce, eventlog, or both

    static StreamWriter logWriter = null;

    static readonly object logWriterLock = new object();

    static void Main(string[] args)
    {
        if (args.Length == 0 || args[0] == "-h" || args[0] == "--help")
        {
            PrintHelp();
            return;
        }

        string basePath = null;
        bool hasBasePath = false;

        // Check if first arg is a path or a flag
        if (args.Length > 0 && !args[0].StartsWith("-"))
        {
            basePath = args[0];
            hasBasePath = true;
        }

        for (int i = hasBasePath ? 1 : 0; i < args.Length; i++)
        {
            if (args[i] == "--max-threads" && i + 1 < args.Length)
            {
                if (int.TryParse(args[i + 1], out int threads))
                {
                    maxThreads = threads;
                    i++;
                }
            }
            else if (args[i] == "--depth" && i + 1 < args.Length)
            {
                if (int.TryParse(args[i + 1], out int depth))
                {
                    maxDepth = depth;
                    i++;
                }
            }
            else if (args[i] == "--output" && i + 1 < args.Length)
            {
                outputFile = args[i + 1];
                i++;
            }
            else if (args[i] == "--verbose")
            {
                verbose = true;
            }
            else if (args[i] == "--method" && i + 1 < args.Length)
            {
                scanMethod = args[i + 1].ToLower();
                i++;
            }
        }

        // Validate method
        if (scanMethod != "bruteforce" && scanMethod != "eventlog" && scanMethod != "both")
        {
            Console.WriteLine($"Error: Invalid method '{scanMethod}'. Use: bruteforce, eventlog, or both");
            return;
        }

        // Validate basePath for bruteforce method
        if ((scanMethod == "bruteforce" || scanMethod == "both") && string.IsNullOrEmpty(basePath))
        {
            Console.WriteLine("Error: Base path required for bruteforce method.");
            PrintHelp();
            return;
        }

        if (outputFile != null)
        {
            try
            {
                logWriter = new StreamWriter(outputFile);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error opening output file {outputFile}: {ex.Message}");
                return;
            }
        }

        stopwatch.Start();

        // Run EventLog method
        if (scanMethod == "eventlog" || scanMethod == "both")
        {
            // Scan event logs silently unless verbose debug is needed
            GetExclusionsFromEventLog();
            if (scanMethod == "eventlog")
            {
                stopwatch.Stop();
                if (verbose) Console.WriteLine($"Event log scan completed. Total time: {stopwatch.Elapsed.TotalSeconds:F2} seconds.");
            }
        }

        // Run BruteForce method
        if (scanMethod == "bruteforce" || scanMethod == "both")
        {
            if (scanMethod == "both" && verbose) Console.WriteLine("\n[*] Starting brute-force scan...");
            GetExcludedFoldersByTier(basePath, 0);
        }

        if (logWriter != null)
        {
            logWriter.Close();
        }
    }

    static void PrintHelp()
    {
        Console.WriteLine("Usage: SharpExclusionFinder.exe [<BasePath>] [options]");
        Console.WriteLine("Authors: Hoshea Yarden, Hai Vaknin, Yehuda Smirnov, Noam Pomerantz, Kasem545");
        Console.WriteLine("Options:");
        Console.WriteLine("  --method <type>      Detection method: bruteforce (default), eventlog, or both");
        Console.WriteLine("  --max-threads N      Set the maximum number of threads (default 3, bruteforce only)");
        Console.WriteLine("  --depth N            Set the maximum directory depth to scan (1 = immediate subdirectories, bruteforce only)");
        Console.WriteLine("  --output <filePath>  Specify a file to log exclusions and errors");
        Console.WriteLine("  --verbose             Show all output (progress, errors). Default: only excluded paths");
        Console.WriteLine("  -h, --help           Display help and usage information");
        Console.WriteLine("");
        Console.WriteLine("Examples:");
        Console.WriteLine("  SharpExclusionFinder.exe --method eventlog");
        Console.WriteLine("  SharpExclusionFinder.exe C:\\\\Users --method bruteforce");
        Console.WriteLine("  SharpExclusionFinder.exe C:\\\\Users --method both --verbose");
    }

    // Get exclusions from Windows Defender Event Logs (Event ID 5007)
    static void GetExclusionsFromEventLog()
    {
        try
        {
            string logName = "Microsoft-Windows-Windows Defender/Operational";
            int eventId = 5007;

            EventLogQuery query = new EventLogQuery(logName, PathType.LogName, $"*[System[EventID={eventId}]]");
            EventLogReader reader = new EventLogReader(query);

            // Patterns to match exclusion registry paths (capture path before the = sign)
            Regex patternPaths = new Regex(@"HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\\([^=\r\n]+)", RegexOptions.IgnoreCase);
            Regex patternExtensions = new Regex(@"HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Extensions\\([^=\r\n]+)", RegexOptions.IgnoreCase);
            Regex patternProcesses = new Regex(@"HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Processes\\([^=\r\n]+)", RegexOptions.IgnoreCase);

            EventRecord eventRecord;
            int count = 0;
            int addedCount = 0;
            int deletedCount = 0;
            int modifiedCount = 0;
            int totalEvents = 0;
            int exclusionEvents = 0;

            // Store exclusions for table display
            var exclusionsList = new List<(string action, string type, string path, DateTime timestamp)>();

            while ((eventRecord = reader.ReadEvent()) != null)
            {
                totalEvents++;
                string message = eventRecord.FormatDescription();
                if (message == null || !message.Contains("Exclusions")) continue;

                exclusionEvents++;

                // Determine if this is an addition or deletion
                // Format: 
                //   Addition: "Old value:\n        New value: HKLM\\...\\path = 0x0"
                //   Deletion: "Old value: HKLM\\...\\path = 0x0\n        New value:"
                string action = "unknown";

                // Split message by lines to check Old/New value content
                string[] lines = message.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);

                bool hasContentInOldValue = false;
                bool hasContentInNewValue = false;
                bool inOldValueSection = false;
                bool inNewValueSection = false;

                foreach (string line in lines)
                {
                    string trimmed = line.Trim();

                    if (trimmed.StartsWith("Old value:", StringComparison.OrdinalIgnoreCase))
                    {
                        inOldValueSection = true;
                        inNewValueSection = false;
                        // Check if there's content on the same line
                        if (trimmed.Length > 10 && trimmed.Contains("Exclusions"))
                        {
                            hasContentInOldValue = true;
                        }
                    }
                    else if (trimmed.StartsWith("New value:", StringComparison.OrdinalIgnoreCase))
                    {
                        inNewValueSection = true;
                        inOldValueSection = false;
                        // Check if there's content on the same line
                        if (trimmed.Length > 10 && trimmed.Contains("Exclusions"))
                        {
                            hasContentInNewValue = true;
                        }
                    }
                    else if (inOldValueSection && trimmed.Contains("Exclusions"))
                    {
                        hasContentInOldValue = true;
                    }
                    else if (inNewValueSection && trimmed.Contains("Exclusions"))
                    {
                        hasContentInNewValue = true;
                    }
                }

                // Determine action based on Old/New value content
                if (hasContentInNewValue && !hasContentInOldValue)
                {
                    action = "added";
                }
                else if (hasContentInOldValue && !hasContentInNewValue)
                {
                    action = "deleted";
                }
                else if (hasContentInOldValue && hasContentInNewValue)
                {
                    action = "modified";
                }

                // Show both additions and deletions by default

                // Check for Path exclusions
                MatchCollection pathMatches = patternPaths.Matches(message);
                foreach (Match match in pathMatches)
                {
                    if (match.Groups.Count > 1)
                    {
                        string exclusionPath = match.Groups[1].Value.Trim();
                        exclusionPath = exclusionPath.Replace("\\\\?\\", "").Trim();
                        if (!string.IsNullOrWhiteSpace(exclusionPath))
                        {
                            exclusionsList.Add((action, "Path", exclusionPath, eventRecord.TimeCreated.Value));
                            count++;
                            if (action == "added") addedCount++;
                            else if (action == "deleted") deletedCount++;
                            else if (action == "modified") modifiedCount++;
                        }
                    }
                }

                // Check for Extension exclusions
                MatchCollection extMatches = patternExtensions.Matches(message);
                foreach (Match match in extMatches)
                {
                    if (match.Groups.Count > 1)
                    {
                        string exclusionExt = match.Groups[1].Value.Trim();
                        exclusionExt = exclusionExt.Replace("\\\\?\\", "").Trim();
                        if (!string.IsNullOrWhiteSpace(exclusionExt))
                        {
                            exclusionsList.Add((action, "Extension", exclusionExt, eventRecord.TimeCreated.Value));
                            count++;
                            if (action == "added") addedCount++;
                            else if (action == "deleted") deletedCount++;
                            else if (action == "modified") modifiedCount++;
                        }
                    }
                }

                // Check for Process exclusions
                MatchCollection procMatches = patternProcesses.Matches(message);
                foreach (Match match in procMatches)
                {
                    if (match.Groups.Count > 1)
                    {
                        string exclusionProc = match.Groups[1].Value.Trim();
                        exclusionProc = exclusionProc.Replace("\\\\?\\", "").Trim();
                        if (!string.IsNullOrWhiteSpace(exclusionProc))
                        {
                            exclusionsList.Add((action, "Process", exclusionProc, eventRecord.TimeCreated.Value));
                            count++;
                            if (action == "added") addedCount++;
                            else if (action == "deleted") deletedCount++;
                            else if (action == "modified") modifiedCount++;
                        }
                    }
                }
            }

            // Sort exclusions by timestamp
            var sortedExclusions = exclusionsList.OrderBy(x => x.timestamp).ToList();

            // Display as table
            if (sortedExclusions.Count > 0)
            {
                if (verbose && exclusionEvents > 2)
                {
                    Console.WriteLine("");
                }

                // Table header
                Console.WriteLine(new string('=', 120));
                Console.WriteLine(string.Format("{0,-10} {1,-12} {2,-70} {3,-25}", "Action", "Type", "Path", "Timestamp"));
                Console.WriteLine(new string('=', 120));

                // Table rows
                foreach (var excl in sortedExclusions)
                {
                    string actionStr = excl.action == "added" ? "[+] Added" : excl.action == "deleted" ? "[-] Deleted" : "[~] Modified";
                    string truncatedPath = excl.path.Length > 70 ? excl.path.Substring(0, 67) + "..." : excl.path;

                    ConsoleColor originalColor = Console.ForegroundColor;
                    if (excl.action == "added")
                        Console.ForegroundColor = ConsoleColor.Green;
                    else if (excl.action == "deleted")
                        Console.ForegroundColor = ConsoleColor.Red;
                    else if (excl.action == "modified")
                        Console.ForegroundColor = ConsoleColor.Yellow;

                    Console.WriteLine(string.Format("{0,-10} {1,-12} {2,-70} {3,-25}", actionStr, excl.type, truncatedPath, excl.timestamp.ToString("MM/dd/yyyy hh:mm:ss tt")));

                    Console.ForegroundColor = originalColor;

                    // Log to file
                    if (logWriter != null)
                    {
                        lock (logWriterLock)
                        {
                            logWriter.WriteLine(string.Format("{0,-10} {1,-12} {2,-70} {3,-25}", actionStr, excl.type, truncatedPath, excl.timestamp.ToString("MM/dd/yyyy hh:mm:ss tt")));
                            logWriter.Flush();
                        }
                    }
                }

                Console.WriteLine(new string('=', 120));
            }
        }
        catch (UnauthorizedAccessException)
        {
            LogMessage("Error: Access denied to Event Logs. Run as Administrator.", isError: true);
        }
        catch (EventLogNotFoundException)
        {
            LogMessage("Error: Windows Defender Event Log not found.", isError: true);
        }
        catch (Exception ex)
        {
            LogMessage($"Error reading Event Logs: {ex.Message}", isError: true);
        }
    }

    // Normalize path to use consistent separators for HashSet comparison
    static string NormalizePath(string path)
    {
        return Path.GetFullPath(path);
    }

    static bool ShouldSuppressAccessDenied(string directory)
    {
        if (string.IsNullOrWhiteSpace(directory))
            return false;

        string normalized = directory.Trim().TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        return suppressedAccessDeniedDirectories.Contains(normalized);
    }

    static void GetExcludedFoldersByTier(string basePath, int currentDepth)
    {
        if (currentDepth > maxDepth)
            return;

        // Check if the base path itself is excluded first
        {
            string command = $@"C:\Program Files\Windows Defender\MpCmdRun.exe";
            string scanArgs = $"-Scan -ScanType 3 -File \"{basePath}\\|*\"";
            string scanOutput = RunProcess(command, scanArgs);
            if (scanOutput.Contains("was skipped"))
            {
                LogMessage($"[+] Folder {basePath} is excluded", isError: false);
                excludedDirectories.Add(NormalizePath(basePath));
                stopwatch.Stop();
                if (verbose) Console.WriteLine($"Base path is excluded. Scan completed. Total time: {stopwatch.Elapsed.TotalSeconds:F2} seconds.");
                return;
            }
        }

        var directoriesByTier = new Queue<List<string>>();
        List<string> currentTierDirectories = new List<string>();

        try
        {
            // First, add the top-level directories (first tier)
            currentTierDirectories.AddRange(Directory.GetDirectories(basePath));
            directoriesByTier.Enqueue(currentTierDirectories);
        }
        catch (Exception ex)
        {
            LogMessage($"Error retrieving top-level directories from {basePath}: {ex.Message}", isError: true);
        }

        // Process each tier until all directories are scanned or max depth is reached
        while (directoriesByTier.Count > 0 && currentDepth <= maxDepth)
        {
            var currentTier = directoriesByTier.Dequeue();

            totalDirectories += currentTier.Count;

            // Filter out excluded directories before processing
            List<string> filteredDirectories = new List<string>();
            foreach (var dir in currentTier)
            {
                if (!IsDirectoryExcluded(dir))
                {
                    filteredDirectories.Add(dir);
                }
            }

            ProcessTierDirectories(filteredDirectories);

            List<string> nextTierDirectories = new List<string>();

            foreach (string dir in filteredDirectories)
            {
                try
                {
                    var subDirs = Directory.GetDirectories(dir);
                    nextTierDirectories.AddRange(subDirs);
                }
                catch (UnauthorizedAccessException)
                {
                    if (!ShouldSuppressAccessDenied(dir))
                    {
                        LogMessage($"Access denied to {dir}. Skipping this directory and its subdirectories.", isError: true);
                    }
                }
                catch (Exception ex)
                {
                    LogMessage($"Error retrieving subdirectories from {dir}: {ex.Message}", isError: true);
                }
            }

            if (nextTierDirectories.Count > 0)
            {
                directoriesByTier.Enqueue(nextTierDirectories);
            }

            currentDepth++;
        }

        // Final message
        if (currentDepth <= maxDepth)
        {
            stopwatch.Stop();
            if (verbose) Console.WriteLine($"Scan completed up to depth {maxDepth}. Total time: {stopwatch.Elapsed.TotalSeconds:F2} seconds.");
        }
    }

    static void ProcessTierDirectories(List<string> directories)
    {
        SemaphoreSlim semaphore = new SemaphoreSlim(maxThreads);

        List<Task> tasks = new List<Task>();

        foreach (string dir in directories)
        {
            semaphore.Wait();

            Task task = Task.Run(() =>
            {
                try
                {
                    ScanDirectory(dir);
                }
                finally
                {
                    semaphore.Release();
                }
            });

            tasks.Add(task);
        }

        Task.WaitAll(tasks.ToArray());
    }

    // Function to scan each directory
    static void ScanDirectory(string currentPath)
    {
        try
        {
            int currentCount = Interlocked.Increment(ref counter);

            // Print every 500 directories processed
            if (currentCount % 500 == 0 && verbose)
            {
                TimeSpan elapsed = stopwatch.Elapsed;
                Console.WriteLine($"Processed {currentCount} directories. Time elapsed: {elapsed.TotalSeconds:F2} seconds.");
            }

            // Run the Windows Defender scan command on the current directory
            string command = $@"C:\Program Files\Windows Defender\MpCmdRun.exe";
            string args = $"-Scan -ScanType 3 -File \"{currentPath}\\|*\"";

            string output = RunProcess(command, args);

            if (output.Contains("was skipped"))
            {
                excludedDirectories.Add(NormalizePath(currentPath));
                if (!IsParentExcluded(currentPath))
                {
                    LogMessage($"[+] Folder {currentPath} is excluded", isError: false);
                }
            }
        }
        catch (UnauthorizedAccessException)
        {
            LogMessage($"Skipping {currentPath} due to UnauthorizedAccessException.", isError: true);
        }
        catch (Exception ex)
        {
            LogMessage($"An error occurred while scanning directory {currentPath}: {ex.Message}", isError: true);
        }
    }

    // Function to check if any parent directory is already excluded
    static bool IsParentExcluded(string directory)
    {
        string parent = Path.GetDirectoryName(directory);
        while (!string.IsNullOrEmpty(parent))
        {
            if (excludedDirectories.Contains(NormalizePath(parent)))
                return true;
            parent = Path.GetDirectoryName(parent);
        }
        return false;
    }

    // Function to check if a directory or its parent is excluded
    static bool IsDirectoryExcluded(string directory)
    {
        string currentDirectory = directory;
        while (!string.IsNullOrEmpty(currentDirectory))
        {
            if (excludedDirectories.Contains(NormalizePath(currentDirectory)))
            {
                return true;
            }
            currentDirectory = Path.GetDirectoryName(currentDirectory);
        }
        return false;
    }

    // Function to run a process and return the output
    static string RunProcess(string command, string arguments)
    {
        try
        {
            ProcessStartInfo processInfo = new ProcessStartInfo(command, arguments)
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using (Process process = Process.Start(processInfo))
            {
                using (StreamReader reader = process.StandardOutput)
                {
                    string result = reader.ReadToEnd();
                    return result;
                }
            }
        }
        catch (Exception ex)
        {
            LogMessage($"Error running process: {ex.Message}", isError: true);
            return string.Empty;
        }
    }

    // Function to log messages with color based on action
    static void LogMessageWithColor(string message, string action)
    {
        // Set color based on action
        ConsoleColor originalColor = Console.ForegroundColor;
        if (action == "added")
        {
            Console.ForegroundColor = ConsoleColor.Green;
        }
        else if (action == "deleted")
        {
            Console.ForegroundColor = ConsoleColor.Red;
        }
        else if (action == "modified")
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
        }

        // Log to file if enabled (log all exclusions: added, deleted, modified)
        if (logWriter != null && (message.Contains("[+]") || message.Contains("[-]") || message.Contains("[~]")))
        {
            lock (logWriterLock)
            {
                logWriter.WriteLine(message);
                logWriter.Flush();
            }
        }

        // Console output with color
        Console.WriteLine(message);

        // Restore original color
        Console.ForegroundColor = originalColor;
    }


    // Function to log messages either to console or output file
    static void LogMessage(string message, bool isError)
    {
        bool isAccessDeniedMessage = message != null && message.IndexOf("access denied", StringComparison.OrdinalIgnoreCase) >= 0;
        if (isAccessDeniedMessage)
        {
            return;
        }

        // Log to file if enabled (errors and exclusions)
        if (logWriter != null && (isError || message.Contains("[+]") || message.Contains("[-]") || message.Contains("[~]")))
        {
            lock (logWriterLock)
            {
                logWriter.WriteLine(message);
                logWriter.Flush();
            }
        }

        // Console output: always show errors and exclusions, or everything if verbose
        bool isExclusion = message.Contains("[+]") || message.Contains("[-]") || message.Contains("[~]");
        if (isError || isExclusion || verbose)
        {
            ConsoleColor originalColor = Console.ForegroundColor;

            if (isError)
            {
                Console.ForegroundColor = ConsoleColor.Red;
            }
            else if (isExclusion)
            {
                if (message.Contains("[+]"))
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                }
                else if (message.Contains("[-]"))
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                }
                else if (message.Contains("[~]"))
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                }
            }

            Console.WriteLine(message);
            Console.ForegroundColor = originalColor;
        }
    }
}
