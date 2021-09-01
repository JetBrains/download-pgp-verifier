using System;
using System.IO;
using System.Net;
using System.Reflection;
using System.Text;
using JetBrains.Annotations;

namespace JetBrains.DownloadPgpVerifier
{
  public static class OpenStreamUtil
  {
    public static TResult OpenStreamFromString<TResult>([NotNull] this string str, [NotNull] Func<Stream, TResult> handler)
    {
      if (handler == null) throw new ArgumentNullException(nameof(handler));
      using var stream = new MemoryStream(Encoding.UTF8.GetBytes(str), false);
      return handler(stream);
    }

    public static TResult OpenStreamFromResource<TResult>([NotNull] this Assembly assembly, [NotNull] string resourceName, [NotNull] Func<Stream, TResult> handler)
    {
      if (assembly == null) throw new ArgumentNullException(nameof(assembly));
      if (handler == null) throw new ArgumentNullException(nameof(handler));
      using var stream = assembly.GetManifestResourceStream(resourceName);
      if (stream == null)
        throw new InvalidOperationException($"Failed to open resource stream for {resourceName}");
      return handler(stream);
    }

    public static TResult OpenStreamFromWeb<TResult>([NotNull] this Uri uri, [NotNull] Func<Stream, TResult> handler)
    {
      if (handler == null) throw new ArgumentNullException(nameof(handler));
      var request = WebRequest.Create(uri);
      request.Method = WebRequestMethods.Http.Get;
      using var response = request.GetResponse();
      using var responseStream = response.GetResponseStream();
      if (responseStream == null)
        throw new InvalidOperationException($"Failed to open response stream for {uri}");
      return handler(responseStream);
    }

    public static TResult OpenSeekableStreamFromWeb<TResult>([NotNull] this Uri uri, [NotNull] Func<Stream, TResult> handler)
    {
      return uri.OpenStreamFromWeb(responseStream =>
        {
          using var fileStream = File.Create(Path.GetTempFileName(), 8192, FileOptions.DeleteOnClose);
          responseStream.CopyTo(fileStream);
          fileStream.Position = 0;
          return handler(fileStream);
        });
    }
  }
}