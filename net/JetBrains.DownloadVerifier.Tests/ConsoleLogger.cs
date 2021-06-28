using System;

namespace JetBrains.DownloadVerifier.Tests
{
  internal sealed class ConsoleLogger : ILogger
  {
    public static readonly ILogger Instance = new ConsoleLogger();

    private ConsoleLogger()
    {
    }

    void ILogger.Info(string str) => Console.WriteLine(str);
    void ILogger.Warning(string str) => Console.Error.WriteLine("WARNING: " + str);
    void ILogger.Error(string str) => Console.Error.WriteLine("ERROR: " + str);
  }
}