using System.ComponentModel;
using System.Diagnostics;
using System.Text;

namespace HappyDocker;

public enum ProcessOutcome { Exited, Missing, Failed, TimedOut, OutputLimit }

public sealed record ProcessCaptureResult(ProcessOutcome Outcome, int ExitCode = -1, string Stdout = "", string Stderr = "");

internal static class ProcessCapture
{
    internal static async Task<ProcessCaptureResult> RunAsync(ProcessStartInfo startInfo, TimeSpan timeout,
        int stdoutLimit, int stderrLimit, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        using var process = new Process { StartInfo = startInfo };
        try
        {
            if (!process.Start()) return new(ProcessOutcome.Failed);
        }
        catch (Win32Exception exception)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return new(exception.NativeErrorCode is 2 or 3 ? ProcessOutcome.Missing : ProcessOutcome.Failed);
        }
        catch (Exception exception) when (exception is IOException or InvalidOperationException or NotSupportedException)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return new(ProcessOutcome.Failed);
        }

        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(timeout);
        int pipeFailure = (int)ProcessOutcome.Exited;
        Stream? stdout = null;
        Stream? stderr = null;
        try
        {
            stdout = process.StandardOutput.BaseStream;
            stderr = process.StandardError.BaseStream;
            Task<string> output = ReadPipeAsync(stdout, stdoutLimit, FailPipe, deadline.Token);
            Task<string> errors = ReadPipeAsync(stderr, stderrLimit, FailPipe, deadline.Token);
            Task completion = Task.WhenAll(output, errors, process.WaitForExitAsync(deadline.Token));
            await completion.WaitAsync(deadline.Token);
            deadline.Token.ThrowIfCancellationRequested();
            return new(ProcessOutcome.Exited, process.ExitCode, await output, await errors);
        }
        catch (OperationCanceledException)
        {
            await StopAsync(process);
            cancellationToken.ThrowIfCancellationRequested();
            var failure = (ProcessOutcome)Volatile.Read(ref pipeFailure);
            return new(failure == ProcessOutcome.Exited ? ProcessOutcome.TimedOut : failure);
        }
        catch (Exception exception) when (exception is IOException or InvalidOperationException or Win32Exception)
        {
            await StopAsync(process);
            cancellationToken.ThrowIfCancellationRequested();
            return new(ProcessOutcome.Failed);
        }
        finally
        {
            ClosePipe(stdout);
            ClosePipe(stderr);
        }

        void FailPipe(ProcessOutcome outcome)
        {
            Interlocked.CompareExchange(ref pipeFailure, (int)outcome, (int)ProcessOutcome.Exited);
            try { deadline.Cancel(); }
            catch (ObjectDisposedException) { }
        }
    }

    private static void ClosePipe(Stream? stream)
    {
        try { stream?.Dispose(); }
        catch (IOException) { }
    }

    internal static async Task<string> ReadPipeAsync(Stream stream, int limit, Action<ProcessOutcome> onFailure, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        using var contents = new MemoryStream();
        byte[] buffer = new byte[8192];
        try
        {
            int read;
            while ((read = await stream.ReadAsync(buffer.AsMemory(), cancellationToken)) != 0)
            {
                if (contents.Length + read > limit)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    onFailure(ProcessOutcome.OutputLimit);
                    return "";
                }
                contents.Write(buffer, 0, read);
            }
            cancellationToken.ThrowIfCancellationRequested();
            return Encoding.UTF8.GetString(contents.GetBuffer(), 0, (int)contents.Length);
        }
        catch (Exception exception) when (exception is IOException or ObjectDisposedException)
        {
            cancellationToken.ThrowIfCancellationRequested();
            onFailure(ProcessOutcome.Failed);
            return "";
        }
    }

    private static async Task StopAsync(Process process)
    {
        try { process.Kill(entireProcessTree: true); }
        catch (InvalidOperationException) { }
        catch (Exception exception) when (exception is Win32Exception or NotSupportedException or IOException)
        {
            try { process.Kill(); }
            catch (Exception fallback) when (fallback is InvalidOperationException or Win32Exception or NotSupportedException or IOException) { }
        }

        using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        try { await process.WaitForExitAsync(cleanup.Token); }
        catch (Exception exception) when (exception is OperationCanceledException or InvalidOperationException or Win32Exception or NotSupportedException or IOException) { }
    }
}
