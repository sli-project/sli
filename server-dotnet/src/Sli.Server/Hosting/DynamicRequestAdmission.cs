using System.Diagnostics;

namespace Sli.Server.Hosting;

// Mirrors the frozen server's exact rolling minute and bounded oldest-first cleanup.
public sealed class DynamicRequestAdmission(int limit, Func<double>? clock = null)
{
    private const int Capacity = 16384;
    private readonly object sync = new();
    private readonly Dictionary<(string, string), LinkedListNode<Entry>> buckets = new();
    private readonly LinkedList<Entry> order = new();
    private readonly Func<double> now = clock ?? (() => (double)Stopwatch.GetTimestamp() / Stopwatch.Frequency);

    private sealed record Entry((string, string) Key, Queue<double> Times)
    {
        public double LastAccepted { get; set; }
    }
    public int BucketCount { get { lock (sync) return buckets.Count; } }

    public bool Admit(string client, string bucket)
    {
        lock (sync)
        {
            double current = now();
            double cutoff = current - 60;
            for (int i = 0; i < 64 && order.First is { } oldest; i++)
            {
                if (oldest.Value.LastAccepted > cutoff) break;
                buckets.Remove(oldest.Value.Key);
                order.RemoveFirst();
            }
            var key = (client, bucket);
            if (!buckets.TryGetValue(key, out var node))
            {
                if (buckets.Count >= Capacity) return false;
                node = order.AddLast(new Entry(key, new Queue<double>()));
                buckets.Add(key, node);
            }
            var times = node.Value.Times;
            while (times.Count > 0 && times.Peek() <= cutoff) times.Dequeue();
            if (times.Count >= limit) return false;
            times.Enqueue(current);
            node.Value.LastAccepted = current;
            order.Remove(node);
            order.AddLast(node);
            return true;
        }
    }
}
