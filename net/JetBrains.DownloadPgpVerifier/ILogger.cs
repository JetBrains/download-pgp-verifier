using JetBrains.Annotations;

namespace JetBrains.DownloadPgpVerifier
{
  public interface ILogger
  {
    void Info([NotNull] string str);
    void Warning([NotNull] string str);
    void Error([NotNull] string str);
  }
}