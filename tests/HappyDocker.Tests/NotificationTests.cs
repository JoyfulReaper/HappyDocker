using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using static HappyDocker.Tests.RegistryFixture;

namespace HappyDocker.Tests;

[TestClass]
public sealed class NotificationTests
{
    private const string Destination = "https://ntfy.example/private-topic";
    private const string Host = "clanker";
    private readonly DirectoryInfo directory = Directory.CreateTempSubdirectory("happydocker-notify-");
    private string Database => Path.Combine(directory.FullName, "findings.db");

    [TestCleanup]
    public void Cleanup()
    {
        foreach (FileInfo file in directory.GetFiles()) file.Delete();
        directory.Delete();
    }

    [TestMethod]
    public async Task NewAndChangedFindingsAreGroupedAndSentOnce()
    {
        var messages = new List<string>();
        using var client = Client(async (request, _) =>
        {
            Assert.AreEqual(HttpMethod.Post, request.Method);
            Assert.AreEqual(Destination, request.RequestUri!.AbsoluteUri);
            Assert.IsNull(request.Headers.Authorization);
            Assert.AreEqual("text/plain", request.Content!.Headers.ContentType!.MediaType);
            messages.Add(await request.Content.ReadAsStringAsync());
            return new(HttpStatusCode.OK);
        });
        var observation = Observation();
        var second = observation with { ContainerName = "nats-two", ContainerId = "two" };
        var run = new FindingRun(0, [observation, second]);
        var options = Options();
        Assert.AreEqual(0, await options.RecordAsync(run, NoDocker, TextWriter.Null, client));
        Assert.HasCount(1, messages);
        Assert.Contains("clanker", messages[0]);
        Assert.Contains("nats, nats-two", messages[0]);
        Assert.Contains("docker.io/library/nats", messages[0]);
        Assert.Contains("Current tag 2.14.8-alpine", messages[0]);
        Assert.Contains("Available " + observation.Available, messages[0]);
        Assert.Contains("New mutable-tag update", messages[0]);
        Assert.Contains("platform verified", messages[0]);
        Assert.AreEqual(0L, Scalar("SELECT count(*) FROM notification_outbox"));

        Assert.AreEqual(0, await options.RecordAsync(run, NoDocker, TextWriter.Null, client));
        Assert.HasCount(1, messages);
        var changed = observation with { Available = "sha256:" + new string('c', 64), ObservedAt = observation.ObservedAt.AddSeconds(1) };
        Assert.AreEqual(0, await options.RecordAsync(new(0, [changed]), NoDocker, TextWriter.Null, client));
        Assert.HasCount(2, messages);
        Assert.Contains("Changed mutable-tag update", messages[1]);
    }

    [TestMethod]
    public void PatchCandidatesWaitForVerificationAndIgnoreIncompleteOrSkippedObservations()
    {
        using var client = Client((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)));
        var patch = Observation() with { Kind = FindingKind.VersionCandidate, Available = "2.14.9-alpine", PlatformVerified = false };
        FindingHistory.Record(Database, Host, [
            patch,
            patch with { ContainerName = "incomplete", Evidence = FindingEvidence.Incomplete },
            patch with { ContainerName = "skip", Evidence = FindingEvidence.NotApplicable },
            patch with { ContainerName = "absent", Evidence = FindingEvidence.Absent }
        ], client.DestinationKey);
        Assert.AreEqual(0L, Scalar("SELECT count(*) FROM notification_outbox"));
        Assert.AreEqual(FindingState.Known, FindingHistory.Record(Database, Host,
            [patch with { PlatformVerified = true, ObservedAt = patch.ObservedAt.AddSeconds(1) }], client.DestinationKey).Single().State);
        Assert.AreEqual(1L, Scalar("SELECT count(*) FROM notification_outbox"));
        Assert.Contains("New patch version candidate", (string)Scalar("SELECT message FROM notification_outbox")!);
        var next = patch with { Available = "2.14.10-alpine", PlatformVerified = true, ObservedAt = patch.ObservedAt.AddSeconds(2) };
        FindingHistory.Record(Database, Host, [next], client.DestinationKey);
        Assert.AreEqual(2L, Scalar("SELECT count(*) FROM notification_outbox"));
        string text = (string)Scalar("SELECT message FROM notification_outbox ORDER BY id DESC LIMIT 1")!;
        Assert.Contains("Changed patch version candidate", text);
        Assert.Contains("Review compatibility and security separately.", text);
        Assert.Contains("2.14.10-alpine", text);
        FindingHistory.Record(Database, Host, [next with { ContainerName = "other", Available = "2.14.11-alpine" }], client.DestinationKey);
        Assert.AreEqual(3L, Scalar("SELECT count(*) FROM notification_outbox"));
    }

    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task DeferredPatchEligibilitySurvivesRunsAndQueuesOneAlertWhenVerified(bool changed)
    {
        int requests = 0;
        using var client = Client((_, _) => Task.FromResult(new HttpResponseMessage(
            ++requests == 1 ? HttpStatusCode.ServiceUnavailable : HttpStatusCode.OK)));
        var patch = Observation() with { Kind = FindingKind.VersionCandidate, Available = "2.14.10-alpine", PlatformVerified = false };
        if (changed)
            FindingHistory.Record(Database, Host, [patch with { Available = "2.14.9-alpine", ObservedAt = patch.ObservedAt.AddSeconds(-1) }]);
        FindingState origin = changed ? FindingState.Changed : FindingState.New;
        Assert.AreEqual(origin, FindingHistory.Record(Database, Host, [patch], client.DestinationKey).Single().State);
        Assert.AreEqual(client.DestinationKey, Scalar("SELECT pending_notification_destination FROM findings"));
        Assert.AreEqual(origin.ToString(), Scalar("SELECT pending_notification_state FROM findings"));
        Assert.AreEqual(0L, Scalar("SELECT count(*) FROM notification_outbox"));
        var repeated = patch with { ObservedAt = patch.ObservedAt.AddSeconds(1), ContainerId = "recreated" };
        Assert.AreEqual(FindingState.Known, FindingHistory.Record(Database, Host, [repeated], client.DestinationKey).Single().State);
        Assert.AreEqual(0, (await NotificationOutbox.DeliverAsync(Database, Host, client)).Pending);
        Assert.AreEqual(0, requests);
        Assert.AreEqual(origin.ToString(), Scalar("SELECT pending_notification_state FROM findings"));

        var verified = repeated with { PlatformVerified = true, ObservedAt = patch.ObservedAt.AddSeconds(2) };
        Assert.AreEqual(FindingState.Known, FindingHistory.Record(Database, Host, [verified], client.DestinationKey).Single().State);
        Assert.AreEqual("Known", Scalar("SELECT state FROM findings"));
        Assert.AreEqual(DBNull.Value, Scalar("SELECT pending_notification_destination FROM findings"));
        Assert.AreEqual(DBNull.Value, Scalar("SELECT pending_notification_state FROM findings"));
        Assert.AreEqual(1L, Scalar("SELECT count(*) FROM notification_outbox"));
        Assert.Contains($"{origin} patch version candidate", (string)Scalar("SELECT message FROM notification_outbox")!);
        Assert.AreEqual(1, (await NotificationOutbox.DeliverAsync(Database, Host, client)).Failed);
        Assert.AreEqual(FindingState.Known, FindingHistory.Record(Database, Host, [verified], client.DestinationKey).Single().State);
        Assert.AreEqual(1L, Scalar("SELECT count(*) FROM notification_outbox"));
        Execute("UPDATE notification_outbox SET next_attempt = 0");
        Assert.AreEqual(1, (await NotificationOutbox.DeliverAsync(Database, Host, client)).Sent);
        FindingHistory.Record(Database, Host, [verified], client.DestinationKey);
        Assert.AreEqual(0L, Scalar("SELECT count(*) FROM notification_outbox"));
        Assert.AreEqual(2, requests);
    }

    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public void EnablingNotificationsForKnownCandidatesDoesNotCreateDeferredEligibility(bool initiallyVerified)
    {
        using var client = Client((_, _) => throw new AssertFailedException("Existing findings are not eligible."));
        var patch = Observation() with { Kind = FindingKind.VersionCandidate, Available = "2.14.9-alpine", PlatformVerified = initiallyVerified };
        FindingHistory.Record(Database, Host, [patch]);
        Assert.AreEqual(FindingState.Known, FindingHistory.Record(Database, Host, [patch]).Single().State);
        Assert.AreEqual(FindingState.Known, FindingHistory.Record(Database, Host, [patch], client.DestinationKey).Single().State);
        Assert.AreEqual(DBNull.Value, Scalar("SELECT pending_notification_destination FROM findings"));
        var verified = patch with { PlatformVerified = true, ObservedAt = patch.ObservedAt.AddSeconds(1) };
        Assert.AreEqual(FindingState.Known, FindingHistory.Record(Database, Host, [verified], client.DestinationKey).Single().State);
        Assert.AreEqual(0L, Scalar("SELECT count(*) FROM notification_outbox"));
    }

    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public void CandidateChangesReplaceObsoleteEligibilityEvenWithNotificationsDisabled(bool notifyOnChange)
    {
        using var client = Client((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)));
        var original = Observation() with { Kind = FindingKind.VersionCandidate, Available = "2.14.9-alpine", PlatformVerified = false };
        FindingHistory.Record(Database, Host, [original], client.DestinationKey);
        var next = original with { Available = "2.14.10-alpine", ObservedAt = original.ObservedAt.AddSeconds(1) };
        Assert.AreEqual(FindingState.Changed, FindingHistory.Record(Database, Host, [next],
            notifyOnChange ? client.DestinationKey : null).Single().State);
        Assert.AreEqual(notifyOnChange ? (object)client.DestinationKey : DBNull.Value,
            Scalar("SELECT pending_notification_destination FROM findings"));
        Assert.AreEqual(FindingState.Known, FindingHistory.Record(Database, Host,
            [next with { PlatformVerified = true, ObservedAt = next.ObservedAt.AddSeconds(1) }], client.DestinationKey).Single().State);
        Assert.IsEmpty(FindingHistory.Record(Database, Host, [original with { PlatformVerified = true }], client.DestinationKey));
        Assert.AreEqual(notifyOnChange ? 1L : 0L, Scalar("SELECT count(*) FROM notification_outbox"));
        if (notifyOnChange)
        {
            string message = (string)Scalar("SELECT message FROM notification_outbox")!;
            Assert.Contains("Changed patch version candidate", message);
            Assert.Contains("2.14.10-alpine", message);
            Assert.DoesNotContain("2.14.9-alpine", message);
        }
    }

    [TestMethod]
    public void DeferredEligibilityIsScopedToItsDestinationAndClearedOnResolution()
    {
        using var client = Client((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)));
        using var other = Client((_, _) => throw new AssertFailedException("Other destination is not eligible."),
            destination: "https://ntfy.example/other");
        var patch = Observation() with { Kind = FindingKind.VersionCandidate, Available = "2.14.9-alpine", PlatformVerified = false };
        FindingHistory.Record(Database, Host, [patch], client.DestinationKey);
        var verified = patch with { PlatformVerified = true, ObservedAt = patch.ObservedAt.AddSeconds(1) };
        FindingHistory.Record(Database, Host, [verified], other.DestinationKey);
        Assert.AreEqual(0L, Scalar("SELECT count(*) FROM notification_outbox"));
        Assert.AreEqual(client.DestinationKey, Scalar("SELECT pending_notification_destination FROM findings"));
        var absent = verified with { Evidence = FindingEvidence.Absent, ObservedAt = verified.ObservedAt.AddSeconds(1) };
        Assert.AreEqual(FindingState.Resolved, FindingHistory.Record(Database, Host, [absent], client.DestinationKey).Single().State);
        Assert.AreEqual(DBNull.Value, Scalar("SELECT pending_notification_destination FROM findings"));
        Assert.AreEqual(DBNull.Value, Scalar("SELECT pending_notification_state FROM findings"));
        Assert.AreEqual(0L, Scalar("SELECT count(*) FROM notification_outbox"));
    }

    [TestMethod]
    public void DeferredEligibilityAndFindingVerificationRollBackIfOutboxEnqueueFails()
    {
        using var client = Client((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)));
        var patch = Observation() with { Kind = FindingKind.VersionCandidate, Available = "2.14.9-alpine", PlatformVerified = false };
        FindingHistory.Record(Database, Host, [patch], client.DestinationKey);
        Execute("""
            CREATE TRIGGER fail_notification BEFORE INSERT ON notification_outbox
            BEGIN SELECT RAISE(ABORT, 'test failure'); END
            """);
        var verified = patch with { PlatformVerified = true, ObservedAt = patch.ObservedAt.AddSeconds(1) };
        Assert.ThrowsExactly<FindingHistoryException>(() => FindingHistory.Record(Database, Host, [verified], client.DestinationKey));
        Assert.AreEqual(client.DestinationKey, Scalar("SELECT pending_notification_destination FROM findings"));
        Assert.AreEqual("New", Scalar("SELECT pending_notification_state FROM findings"));
        Assert.AreEqual(0L, Scalar("SELECT platform_verified FROM findings"));
        Assert.AreEqual(0L, Scalar("SELECT count(*) FROM notification_outbox"));
        Execute("DROP TRIGGER fail_notification");
        Assert.AreEqual(FindingState.Known, FindingHistory.Record(Database, Host, [verified], client.DestinationKey).Single().State);
        Assert.AreEqual(DBNull.Value, Scalar("SELECT pending_notification_destination FROM findings"));
        Assert.AreEqual(1L, Scalar("SELECT count(*) FROM notification_outbox"));
    }

    [TestMethod]
    public async Task ConcurrentVerificationConsumesDeferredEligibilityOnce()
    {
        using var client = Client((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)));
        var patch = Observation() with { Kind = FindingKind.VersionCandidate, Available = "2.14.9-alpine", PlatformVerified = false };
        FindingHistory.Record(Database, Host, [patch], client.DestinationKey);
        var verified = patch with { PlatformVerified = true, ObservedAt = patch.ObservedAt.AddSeconds(1) };
        var results = await Task.WhenAll(Enumerable.Range(0, 4).Select(_ => Task.Run(() =>
            FindingHistory.Record(Database, Host, [verified], client.DestinationKey))));
        Assert.IsTrue(results.All(transitions => transitions.Single().State == FindingState.Known));
        Assert.AreEqual(1L, Scalar("SELECT count(*) FROM notification_outbox"));
        Assert.AreEqual(DBNull.Value, Scalar("SELECT pending_notification_destination FROM findings"));
    }

    [TestMethod]
    public async Task TemporaryVerificationFailureKeepsStrongerEvidenceWithoutRenewingEligibility()
    {
        using var fixture = new RegistryFixture(tag: "2.14.8-alpine");
        fixture.Image = fixture.Image with
        {
            Identity = JsonSerializer.SerializeToElement(new { Pull = new[] { new { Repository = "docker.io/library/nats" } } })
        };
        fixture.SetTag(fixture.NewManifest, "2.14.9-alpine");
        fixture.Intercept = request => IsTagList(request) ? Tags() : null;
        int sent = 0;
        using var client = Client((_, _) =>
        {
            sent++;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        });
        Assert.AreEqual(0, await Options().RecordAsync(await RunVersions(), NoDocker, TextWriter.Null, client));
        Assert.AreEqual(1, sent);
        fixture.Intercept = request => IsTagList(request) ? Tags() : Error(HttpStatusCode.ServiceUnavailable);
        var failed = await RunVersions();
        Assert.IsFalse(failed.Observations.Single().PlatformVerified ?? true);
        Assert.AreEqual(FindingRunStatus.Partial, failed.Status);
        Assert.AreEqual(2, await Options().RecordAsync(failed, NoDocker, TextWriter.Null, client));
        Assert.AreEqual("Known", Scalar("SELECT state FROM findings"));
        Assert.AreEqual(1L, Scalar("SELECT platform_verified FROM findings"));
        Assert.AreEqual(DBNull.Value, Scalar("SELECT pending_notification_destination FROM findings"));
        Assert.AreEqual(0L, Scalar("SELECT count(*) FROM notification_outbox"));
        Assert.AreEqual(1, sent);

        Task<FindingRun> RunVersions() => DockerVersions.RunObservedAsync(["--repo", "nats"], args =>
            Task.FromResult(new DockerCommandResult(0, args[0] switch
            {
                "ps" => Lines(new[] { new { ID = fixture.Container.Id, Names = fixture.Container.Name, Image = fixture.Container.ConfiguredImage } }),
                "inspect" => Lines(new[] { fixture.Container }),
                "image" => Lines(new[] { fixture.Image }),
                _ => throw new AssertFailedException("Unexpected Docker operation.")
            }, "")), fixture.Client, TextWriter.Null, TextWriter.Null);
        static bool IsTagList(HttpRequestMessage request) => request.RequestUri!.AbsolutePath.EndsWith("/tags/list", StringComparison.Ordinal);
        static HttpResponseMessage Tags() => Response(JsonSerializer.SerializeToUtf8Bytes(
            new { name = "library/nats", tags = new[] { "2.14.9-alpine" } }));
    }

    [TestMethod]
    [DataRow(1)]
    [DataRow(2)]
    public void EarlierSchemasGainEligibilityColumnsWithoutRetroactiveAlerts(int version)
    {
        using var client = Client((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)));
        var patch = Observation() with { Kind = FindingKind.VersionCandidate, Available = "2.14.9-alpine", PlatformVerified = false };
        FindingHistory.Record(Database, Host, [patch]);
        Execute("""
            ALTER TABLE findings DROP COLUMN pending_notification_state;
            ALTER TABLE findings DROP COLUMN pending_notification_destination;
            """);
        Execute("DROP TABLE version_discovery_cache; PRAGMA user_version = 2");
        if (version == 1) Execute("DROP TABLE notification_outbox; PRAGMA user_version = 1");
        var verified = patch with { PlatformVerified = true, ObservedAt = patch.ObservedAt.AddSeconds(1) };
        Assert.AreEqual(FindingState.Known, FindingHistory.Record(Database, Host, [verified], client.DestinationKey).Single().State);
        Assert.AreEqual(5L, Scalar("PRAGMA user_version"));
        Assert.AreEqual(1L, Scalar("SELECT count(*) FROM findings"));
        Assert.AreEqual(0L, Scalar("SELECT count(*) FROM notification_outbox"));
        Assert.AreEqual(DBNull.Value, Scalar("SELECT pending_notification_destination FROM findings"));
    }

    [TestMethod]
    public async Task FailedDeliveryPersistsAndRetriesOnAnEmptyInvocation()
    {
        int requests = 0;
        using var client = Client((_, _) =>
            Task.FromResult(new HttpResponseMessage(++requests == 1 ? HttpStatusCode.ServiceUnavailable : HttpStatusCode.Accepted)));
        using var output = new StringWriter();
        Assert.AreEqual(3, await Options().RecordAsync(new(0, [Observation()]), NoDocker, output, client));
        Assert.Contains("Finding history complete.", output.ToString());
        Assert.Contains("Notifications sent 0, failed 1, pending 1", output.ToString());
        Assert.Contains("HTTP 503", output.ToString());
        Assert.AreEqual(1L, Scalar("SELECT count(*) FROM findings"));
        Assert.AreEqual(1L, Scalar("SELECT count(*) FROM notification_outbox"));
        Assert.AreEqual(1L, Scalar("SELECT attempts FROM notification_outbox"));
        Assert.AreEqual(0L, Scalar("SELECT lease_until FROM notification_outbox"));
        Assert.AreEqual(3, await Options().RecordAsync(new(0, []), NoDocker, TextWriter.Null, client));
        Assert.AreEqual(1, requests); // The saved retry deadline is respected.
        Execute("UPDATE notification_outbox SET next_attempt = 0");
        Assert.AreEqual(0, await Options().RecordAsync(new(0, []), NoDocker, TextWriter.Null, client));
        Assert.AreEqual(2, requests);
        Assert.AreEqual(0L, Scalar("SELECT count(*) FROM notification_outbox"));
    }

    [TestMethod]
    [DataRow(401)]
    [DataRow(403)]
    [DataRow(302)]
    [DataRow(400)]
    [DataRow(500)]
    public async Task HttpErrorsAndRedirectsRemainPendingWithoutLeakingResponseContent(int code)
    {
        int requests = 0;
        using var client = Client((_, _) =>
        {
            requests++;
            return Task.FromResult(new HttpResponseMessage((HttpStatusCode)code)
            {
                Content = new StringContent("sensitive response body"),
                Headers = { Location = new Uri("https://other.example/leak") }
            });
        });
        using var output = new StringWriter();
        Assert.AreEqual(3, await Options().RecordAsync(new(0, [Observation()]), NoDocker, output, client));
        Assert.AreEqual(1, requests);
        Assert.AreEqual(1L, Scalar("SELECT count(*) FROM notification_outbox"));
        Assert.DoesNotContain("sensitive response body", output.ToString());
        Assert.DoesNotContain("other.example", output.ToString());
    }

    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task RateLimitDefersTheEntireDestinationAndHonorsRetryAfter(bool absolute)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow.AddSeconds(2);
        var clock = new TestClock(now);
        int requests = 0;
        using var client = Client((_, _) =>
        {
            requests++;
            var response = new HttpResponseMessage(HttpStatusCode.TooManyRequests);
            response.Headers.RetryAfter = absolute ? new RetryConditionHeaderValue(now.AddMinutes(10))
                : new RetryConditionHeaderValue(TimeSpan.FromMinutes(10));
            return Task.FromResult(response);
        });
        FindingHistory.Record(Database, Host, [Observation(), Observation() with { ContainerName = "redis", Repository = "docker.io/library/redis" }],
            client.DestinationKey);
        var result = await NotificationOutbox.DeliverAsync(Database, Host, client, timeProvider: clock);
        Assert.AreEqual(1, result.Failed);
        Assert.AreEqual(2, result.Pending);
        Assert.AreEqual(now.AddMinutes(10).ToUnixTimeSeconds(), Scalar("SELECT MIN(next_attempt) FROM notification_outbox"));
        FindingHistory.Record(Database, Host, [Observation() with { ContainerName = "extra" }], client.DestinationKey);
        Assert.AreEqual(now.AddMinutes(10).ToUnixTimeSeconds(), Scalar("SELECT MIN(next_attempt) FROM notification_outbox"));
        Assert.AreEqual(3, (await NotificationOutbox.DeliverAsync(Database, Host, client, timeProvider: clock)).Pending);
        Assert.AreEqual(1, requests);
    }

    [TestMethod]
    public async Task NetworkErrorsTimeoutsAndCancellationPreservePendingWork()
    {
        using var unavailable = Client((_, _) => throw new HttpRequestException("sensitive destination and credentials"));
        FindingHistory.Record(Database, Host, [Observation()], unavailable.DestinationKey);
        var error = await NotificationOutbox.DeliverAsync(Database, Host, unavailable);
        Assert.AreEqual("ntfy network request failed.", error.Failure);

        Execute("UPDATE notification_outbox SET next_attempt = 0");
        using var timeout = Client(async (_, token) =>
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, token);
            throw new AssertFailedException("Request should time out.");
        }, timeout: TimeSpan.FromMilliseconds(25));
        Assert.AreEqual("ntfy request timed out.", (await NotificationOutbox.DeliverAsync(Database, Host, timeout)).Failure);
        Assert.AreEqual(0L, Scalar("SELECT lease_until FROM notification_outbox"));

        Execute("UPDATE notification_outbox SET next_attempt = 0");
        using var cancellation = new CancellationTokenSource();
        using var cancelled = Client((_, token) =>
        {
            cancellation.Cancel();
            token.ThrowIfCancellationRequested();
            throw new AssertFailedException("Request should be cancelled.");
        });
        await Assert.ThrowsExactlyAsync<OperationCanceledException>(() =>
            NotificationOutbox.DeliverAsync(Database, Host, cancelled, cancellation.Token));
        Assert.AreEqual(1L, Scalar("SELECT count(*) FROM notification_outbox"));
        Assert.AreEqual(0L, Scalar("SELECT lease_until FROM notification_outbox"));
    }

    [TestMethod]
    public async Task ConcurrentInvocationsQueueAndDeliverOneTransition()
    {
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        int requests = 0;
        using var client = Client(async (_, _) =>
        {
            Interlocked.Increment(ref requests);
            started.SetResult();
            await release.Task;
            return new(HttpStatusCode.OK);
        });
        var observation = Observation();
        var records = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => Task.Run(() =>
            FindingHistory.Record(Database, Host, [observation], client.DestinationKey))));
        Assert.HasCount(1, records.SelectMany(item => item).Where(item => item.State == FindingState.New));
        Assert.AreEqual(1L, Scalar("SELECT count(*) FROM notification_outbox"));
        Task<NotificationDeliverySummary> first = NotificationOutbox.DeliverAsync(Database, Host, client);
        await started.Task.WaitAsync(TimeSpan.FromSeconds(5));
        var second = await NotificationOutbox.DeliverAsync(Database, Host, client);
        Assert.AreEqual(0, second.Sent);
        Assert.AreEqual(1, second.Pending);
        release.SetResult();
        Assert.AreEqual(1, (await first).Sent);
        Assert.AreEqual(1, requests);
        Assert.AreEqual(0L, Scalar("SELECT count(*) FROM notification_outbox"));
    }

    [TestMethod]
    public async Task ExpiredDeliveryCannotAcknowledgeANewerLeaseOrReusedRow()
    {
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var paused = Client(async (_, _) =>
        {
            started.SetResult();
            await release.Task;
            return new(HttpStatusCode.OK);
        });
        using var recovery = Client((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)));
        var observation = Observation();
        FindingHistory.Record(Database, Host, [observation], paused.DestinationKey);
        Task<NotificationDeliverySummary> first = NotificationOutbox.DeliverAsync(Database, Host, paused);
        await started.Task.WaitAsync(TimeSpan.FromSeconds(5));
        var future = new TestClock(DateTimeOffset.UtcNow.AddMinutes(2));
        Assert.AreEqual(1, (await NotificationOutbox.DeliverAsync(Database, Host, recovery, timeProvider: future)).Sent);
        FindingHistory.Record(Database, Host, [observation with
        {
            Available = "sha256:" + new string('d', 64), ObservedAt = observation.ObservedAt.AddSeconds(1)
        }], paused.DestinationKey);
        Execute($"UPDATE notification_outbox SET next_attempt = {DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds()}");
        release.SetResult();
        Assert.AreEqual(1, (await first).Sent);
        Assert.AreEqual(1L, Scalar("SELECT count(*) FROM notification_outbox"));
        Assert.Contains(new string('d', 64), (string)Scalar("SELECT message FROM notification_outbox")!);
    }

    [TestMethod]
    public async Task AbandonedLeaseCanBeRecoveredAndDestinationsAndHostsAreIsolated()
    {
        using var client = Client((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)));
        using var other = Client((_, _) => throw new AssertFailedException("Wrong destination."), destination: "https://ntfy.example/other");
        FindingHistory.Record(Database, Host, [Observation()], client.DestinationKey);
        DateTimeOffset now = DateTimeOffset.UtcNow.AddSeconds(2);
        Execute($"UPDATE notification_outbox SET lease_token = 'abandoned', lease_until = {now.AddSeconds(60).ToUnixTimeSeconds()}");
        Assert.AreEqual(0, (await NotificationOutbox.DeliverAsync(Database, Host, other)).Pending);
        Assert.AreEqual(0, (await NotificationOutbox.DeliverAsync(Database, "other-host", client)).Pending);
        Assert.AreEqual(1, (await NotificationOutbox.DeliverAsync(Database, Host, client, timeProvider: new TestClock(now))).Pending);
        Assert.AreEqual(1, (await NotificationOutbox.DeliverAsync(Database, Host, client, timeProvider: new TestClock(now.AddSeconds(61)))).Sent);
    }

    [TestMethod]
    public async Task RetryBatchHasAnUpperBound()
    {
        using var client = Client((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)));
        for (int index = 0; index < 12; index++)
            FindingHistory.Record(Database, Host, [Observation() with { Repository = $"docker.io/library/app-{index}" }], client.DestinationKey);
        var result = await NotificationOutbox.DeliverAsync(Database, Host, client);
        Assert.AreEqual(10, result.Sent);
        Assert.AreEqual(2, result.Pending);
        Assert.AreEqual(2, (await NotificationOutbox.DeliverAsync(Database, Host, client)).Sent);
    }

    [TestMethod]
    public async Task VersionOneMigrationPreservesKnownHistoryWithoutRetroactiveNotifications()
    {
        var observation = Observation();
        FindingHistory.Record(Database, Host, [observation]);
        Execute("DROP TABLE notification_outbox; PRAGMA user_version = 1");
        using var client = Client((_, _) => throw new AssertFailedException("Known findings should not be sent."));
        Assert.AreEqual(0, await Options().RecordAsync(new(0, [observation]), NoDocker, TextWriter.Null, client));
        Assert.AreEqual(5L, Scalar("PRAGMA user_version"));
        Assert.AreEqual(1L, Scalar("SELECT count(*) FROM findings"));
        Assert.AreEqual(observation.Available, Scalar("SELECT available FROM findings"));
        Assert.AreEqual("Known", Scalar("SELECT state FROM findings"));
        Assert.AreEqual(0L, Scalar("SELECT count(*) FROM notification_outbox"));
    }

    [TestMethod]
    public async Task ConcurrentMigrationPreservesHistoryAndQueuesOneChange()
    {
        var original = Observation();
        FindingHistory.Record(Database, Host, [original]);
        Execute("DROP TABLE notification_outbox; PRAGMA user_version = 1");
        string firstObserved = (string)Scalar("SELECT first_observed FROM findings")!;
        using var client = Client((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)));
        var changed = original with { Available = "sha256:" + new string('c', 64), ObservedAt = original.ObservedAt.AddSeconds(1) };
        var runs = await Task.WhenAll(Enumerable.Range(0, 2).Select(_ => Task.Run(() =>
            FindingHistory.Record(Database, Host, [changed], client.DestinationKey))));
        Assert.HasCount(1, runs.SelectMany(run => run).Where(transition => transition.State == FindingState.Changed));
        Assert.AreEqual(5L, Scalar("PRAGMA user_version"));
        Assert.AreEqual(firstObserved, Scalar("SELECT first_observed FROM findings"));
        Assert.AreEqual(1L, Scalar("SELECT count(*) FROM notification_outbox"));
    }

    [TestMethod]
    [DataRow(401)]
    [DataRow(429)]
    [DataRow(500)]
    [DataRow(200)]
    public async Task Versions_NotifiesVerifiedCandidateAndLeavesRegistryFailuresQuiet(int status)
    {
        using var fixture = new RegistryFixture(tag: "2.14.8-alpine");
        fixture.Image = fixture.Image with
        {
            Identity = JsonSerializer.SerializeToElement(new { Pull = new[] { new { Repository = "docker.io/library/nats" } } })
        };
        fixture.SetTag(fixture.NewManifest, "2.14.9-alpine");
        fixture.Intercept = request => IsTagList(request) ? Tags(null) : null;
        int notifications = 0;
        using var client = Client((_, _) =>
        {
            notifications++;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        });
        Assert.AreEqual(0, await Options().RecordAsync(await RunVersions(), NoDocker, TextWriter.Null, client));
        Assert.AreEqual(1, notifications);
        fixture.Intercept = request => IsTagList(request)
            ? status == 200 ? Tags("<https://other.example/tags>; rel=\"next\"") : Error((HttpStatusCode)status)
            : null;
        var failed = await RunVersions();
        Assert.AreEqual(FindingRunStatus.Failed, failed.Status);
        Assert.AreEqual(1, await Options().RecordAsync(failed, NoDocker, TextWriter.Null, client));
        Assert.AreEqual(1, notifications);
        Assert.AreEqual("New", Scalar("SELECT state FROM findings"));
        Assert.AreEqual(0L, Scalar("SELECT count(*) FROM notification_outbox"));

        Task<FindingRun> RunVersions() => DockerVersions.RunObservedAsync(["--repo", "nats"], args =>
            Task.FromResult(new DockerCommandResult(0, args[0] switch
            {
                "ps" => Lines(new[] { new { ID = fixture.Container.Id, Names = fixture.Container.Name, Image = fixture.Container.ConfiguredImage } }),
                "inspect" => Lines(new[] { fixture.Container }),
                "image" => Lines(new[] { fixture.Image }),
                _ => throw new AssertFailedException("Unexpected Docker operation.")
            }, "")), fixture.Client, TextWriter.Null, TextWriter.Null);
        static bool IsTagList(HttpRequestMessage request) => request.RequestUri!.AbsolutePath.EndsWith("/tags/list", StringComparison.Ordinal);
        static HttpResponseMessage Tags(string? link)
        {
            var response = Response(JsonSerializer.SerializeToUtf8Bytes(new { name = "library/nats", tags = new[] { "2.14.9-alpine" } }));
            if (link is not null) response.Headers.TryAddWithoutValidation("Link", link);
            return response;
        }
    }

    [TestMethod]
    public void FindingAndOutboxWritesRollbackTogether()
    {
        FindingHistory.Record(Database, Host, []);
        Execute("""
            CREATE TRIGGER fail_notification BEFORE INSERT ON notification_outbox
            BEGIN SELECT RAISE(ABORT, 'test failure'); END
            """);
        Assert.ThrowsExactly<FindingHistoryException>(() =>
            FindingHistory.Record(Database, Host, [Observation()], "destination-key"));
        Assert.AreEqual(0L, Scalar("SELECT count(*) FROM findings"));
        Assert.AreEqual(0L, Scalar("SELECT count(*) FROM notification_outbox"));
    }

    [TestMethod]
    public async Task DisabledNotificationsIgnoreCredentialsAndKeepTheExistingStateReport()
    {
        using var client = Client((_, _) => throw new AssertFailedException("Notifications are disabled."));
        var options = new FindingStateOptions([], Database, Host);
        using var output = new StringWriter();
        Assert.AreEqual(0, await options.RecordAsync(new(0, [Observation()]), NoDocker, output, client));
        Assert.AreEqual("Finding history complete. New 1, known 0, changed 0, resolved 0, incomplete 0." + Environment.NewLine, output.ToString());
        Assert.AreEqual(0L, Scalar("SELECT count(*) FROM notification_outbox"));
    }

    [TestMethod]
    public async Task ClankerInventoryGroupsTwentyFourUpdatesAndSkipsFiveLocalBuilds()
    {
        using var fixture = new RegistryFixture();
        fixture.SetTag(fixture.NewManifest);
        var localImage = fixture.Image with { Id = Digest(fixture.NewConfig),
            Identity = JsonSerializer.SerializeToElement(new { Build = new[] { new { Ref = "local" } } }) };
        DockerInspectRow[] containers = [
            .. Enumerable.Range(0, 24).Select(i => fixture.Container with { Id = $"pulled-{i}", Name = $"/pulled-{i}" }),
            .. Enumerable.Range(0, 5).Select(i => fixture.Container with { Id = $"local-{i}", Name = $"/local-{i}", ImageId = localImage.Id })
        ];
        var run = await DockerCheck.RunObservedAsync(args => Task.FromResult(new DockerCommandResult(0, args[0] switch
        {
            "ps" => Lines(containers.Select(item => new { ID = item.Id, Names = item.Name, Image = item.ConfiguredImage })),
            "inspect" when args[1] == "--type" => Lines(containers),
            "image" when args[1] == "inspect" => Lines(new[] { fixture.Image, localImage }),
            _ => throw new AssertFailedException("Unexpected Docker operation.")
        }, "")), fixture.Checker, TextWriter.Null, TextWriter.Null);
        Assert.AreEqual(FindingRunStatus.Complete, run.Status);
        Assert.AreEqual(0, run.IncompleteCount);
        Assert.HasCount(5, run.Observations.Where(item => item.Evidence == FindingEvidence.NotApplicable));
        int notifications = 0;
        using var client = Client(async (request, _) =>
        {
            notifications++;
            string message = await request.Content!.ReadAsStringAsync();
            Assert.Contains("(+14 more)", message);
            Assert.DoesNotContain("local-", message);
            Assert.IsLessThanOrEqualTo(NtfyClient.MaximumMessageBytes, Encoding.UTF8.GetByteCount(message));
            return new(HttpStatusCode.OK);
        });
        Assert.AreEqual(0, await Options().RecordAsync(run, NoDocker, TextWriter.Null, client));
        Assert.AreEqual(1, notifications);
        Assert.AreEqual(24L, Scalar("SELECT count(*) FROM findings"));
        Assert.AreEqual(0L, Scalar("SELECT count(*) FROM notification_outbox"));
    }

    [TestMethod]
    public async Task TokenFileIsUsedOnlyForNtfyAndExcludedFromDatabaseAndDiagnostics()
    {
        const string token = "tk_fixture_secret_for_notification_tests";
        string path = Path.Combine(directory.FullName, "ntfy-token");
        File.WriteAllText(path, token + "\n");
        using var client = Client((request, _) =>
        {
            Assert.AreEqual(new AuthenticationHeaderValue("Bearer", token), request.Headers.Authorization);
            throw new HttpRequestException(token);
        }, tokenFile: path);
        using var output = new StringWriter();
        Assert.AreEqual(3, await Options().RecordAsync(new(0, [Observation()]), NoDocker, output, client));
        Assert.DoesNotContain(token, output.ToString());
        Assert.DoesNotContain(token, client.ToString()!);
        Assert.DoesNotContain(token, Encoding.UTF8.GetString(File.ReadAllBytes(Database)));
        Assert.DoesNotContain("private-topic", Encoding.UTF8.GetString(File.ReadAllBytes(Database)));
        using var registry = new RegistryFixture();
        await registry.CheckAsync();
        Assert.IsFalse(registry.Requests.Any(request => request.Authorization?.Contains(token, StringComparison.Ordinal) == true));
        var invalid = Assert.ThrowsExactly<NtfyConfigurationException>(() => new NtfyClient("http://ntfy.example/topic", path));
        Assert.DoesNotContain(token, invalid.ToString());
    }

    [TestMethod]
    [DoNotParallelize]
    public void DockerChildEnvironmentExcludesNtfyConfiguration()
    {
        string? previous = Environment.GetEnvironmentVariable(NtfyClient.TokenFileVariable);
        try
        {
            Environment.SetEnvironmentVariable(NtfyClient.TokenFileVariable, "private-token-file");
            var info = DockerProcess.CreateStartInfo(["image", "inspect", "immutable-image-id"]);
            Assert.IsFalse(info.Environment.ContainsKey(NtfyClient.TokenFileVariable));
            CollectionAssert.AreEqual(new[] { "image", "inspect", "immutable-image-id" }, info.ArgumentList.ToArray());
            Assert.IsFalse(info.UseShellExecute);
        }
        finally { Environment.SetEnvironmentVariable(NtfyClient.TokenFileVariable, previous); }
    }

    [TestMethod]
    [DoNotParallelize]
    public async Task CredentialLoadFailureLeavesCommittedObservationsQueued()
    {
        string? previous = Environment.GetEnvironmentVariable(NtfyClient.TokenFileVariable);
        string missingFile = Path.Combine(directory.FullName, "missing-secret-file");
        try
        {
            Environment.SetEnvironmentVariable(NtfyClient.TokenFileVariable, missingFile);
            using var output = new StringWriter();
            Assert.AreEqual(3, await Options().RecordAsync(new(0, [Observation()]), NoDocker, output));
            Assert.AreEqual(1L, Scalar("SELECT count(*) FROM findings"));
            Assert.AreEqual(1L, Scalar("SELECT count(*) FROM notification_outbox"));
            Assert.Contains("Notifications unavailable.", output.ToString());
            Assert.DoesNotContain(missingFile, output.ToString());
            var disabled = new FindingStateOptions([], Database, Host);
            Assert.AreEqual(0, await disabled.RecordAsync(new(0, [Observation()]), NoDocker, TextWriter.Null));
        }
        finally { Environment.SetEnvironmentVariable(NtfyClient.TokenFileVariable, previous); }
    }

    [TestMethod]
    [DataRow("")]
    [DataRow("https://ntfy.example")]
    [DataRow("http://user:password@ntfy.example/topic")]
    [DataRow("https://ntfy.example/topic?token=secret")]
    [DataRow("https://ntfy.example/topic#fragment")]
    [DataRow("ftp://ntfy.example/topic")]
    public void UnsafeDestinationsAreRejected(string destination) =>
        Assert.IsFalse(FindingStateOptions.TryParse(["--state", Database, "--notify-ntfy", destination], out _));

    [TestMethod]
    public void NotificationOptionsRequireStateAndRejectRepeatedFlags()
    {
        Assert.IsFalse(FindingStateOptions.TryParse(["--notify-ntfy", Destination], out _));
        Assert.IsFalse(FindingStateOptions.TryParse(["--state", Database, "--notify-ntfy", Destination, "--notify-ntfy", Destination], out _));
        Assert.IsTrue(FindingStateOptions.TryParse(["--repo", "nats", "--notify-ntfy", Destination, "--state", Database, "--host", Host], out var options));
        CollectionAssert.AreEqual(new[] { "--repo", "nats" }, options.CommandArguments);
        Assert.AreEqual(Destination, options.NotifyNtfy);
        using var anonymousHttp = new NtfyClient("http://ntfy.example/topic");
        Assert.IsNotNull(anonymousHttp);
    }

    [TestMethod]
    [DataRow("")]
    [DataRow("bad token")]
    [DataRow("bad\ntoken")]
    [DataRow("bad=token")]
    public void InvalidTokenFilesHaveSafeDiagnostics(string contents)
    {
        string path = Path.Combine(directory.FullName, "invalid-token");
        File.WriteAllText(path, contents);
        var error = Assert.ThrowsExactly<NtfyConfigurationException>(() => new NtfyClient(Destination, path));
        Assert.Contains(NtfyClient.TokenFileVariable, error.Message);
        Assert.DoesNotContain(path, error.ToString());
        if (contents.Length > 0) Assert.DoesNotContain(contents, error.ToString());
    }

    [TestMethod]
    public async Task OversizedMessagesAreRejectedBeforeHttp()
    {
        using var client = Client((_, _) => throw new AssertFailedException("Oversized request should be blocked."));
        Assert.IsFalse((await client.SendAsync(new string('x', NtfyClient.MaximumMessageBytes + 1), DateTimeOffset.UtcNow)).Successful);
    }

    private static FindingObservation Observation() => new(FindingKind.MutableTag, "nats", "container", "image",
        "docker.io/library/nats", "2.14.8-alpine", "sha256:" + new string('a', 64), "sha256:" + new string('b', 64),
        true, FindingEvidence.Present, DateTimeOffset.UtcNow);

    private FindingStateOptions Options() => new([], Database, Host, Destination);
    private static Task<DockerCommandResult> NoDocker(string[] _) => throw new AssertFailedException("Explicit host requires no Docker info.");
    private static NtfyClient Client(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send,
        string destination = Destination, string? tokenFile = null, TimeSpan? timeout = null) =>
        new(destination, tokenFile, new FakeRegistryHandler(send), timeout);

    private object? Scalar(string sql)
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        return command.ExecuteScalar();
    }

    private void Execute(string sql)
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        command.ExecuteNonQuery();
    }

    private SqliteConnection Open()
    {
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = Database, Pooling = false }.ToString());
        connection.Open();
        return connection;
    }

    private static string Lines<T>(IEnumerable<T> rows) => string.Join('\n', rows.Select(row => JsonSerializer.Serialize(row)));
    private sealed class TestClock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
