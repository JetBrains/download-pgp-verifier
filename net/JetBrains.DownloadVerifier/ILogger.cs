using JetBrains.Annotations;

namespace JetBrains.DownloadVerifier
{
  public interface ILogger
  {
    void Info([NotNull] string str);
    void Warning([NotNull] string str);
    void Error([NotNull] string str);
  }
}