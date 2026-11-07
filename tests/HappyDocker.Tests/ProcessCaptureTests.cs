using System.Diagnostics;

namespace HappyDocker.Tests;

[TestClass]
public sealed class ProcessCaptureTests
{
    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task BrokenPipeAfterPartialRead_DiscardsOutputAndSignalsFailure(bool disposed)
    {
        using var stream = new BrokenPipe(disposed);
        var outcomes = new List<ProcessOutcome>();
        Assert.AreEqual("", await ProcessCapture.ReadPipeAsync(stream, 100, outcomes.Add, default));
        CollectionAssert.AreEqual(new[] { ProcessOutcome.Failed }, outcomes);
    }

    [TestMethod]
    public async Task PipeIOExceptionRacingCancellation_PropagatesCancellation()
    {
        using var source = new CancellationTokenSource();
        using var stream = new BrokenPipe(false, source.Cancel);
        await Assert.ThrowsAsync<OperationCanceledException>(() =>
            ProcessCapture.ReadPipeAsync(stream, 100, _ => Assert.Fail("Cancellation must not be recorded as a pipe failure."), source.Token));
    }

    [TestMethod]
    public async Task InvalidStartupState_ReturnsControlledFailure()
    {
        var result = await ProcessCapture.RunAsync(new ProcessStartInfo { UseShellExecute = false },
            TimeSpan.FromSeconds(1), 100, 100, default);
        Assert.AreEqual(ProcessOutcome.Failed, result.Outcome);
    }

    private sealed class BrokenPipe(bool disposed, Action? beforeFailure = null) : MemoryStream
    {
        private bool read;

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (!read)
            {
                read = true;
                buffer.Span[0] = (byte)'{';
                return ValueTask.FromResult(1);
            }
            beforeFailure?.Invoke();
            return ValueTask.FromException<int>(disposed
                ? new ObjectDisposedException(nameof(BrokenPipe))
                : new IOException("Pipe read failed."));
        }
    }
}
