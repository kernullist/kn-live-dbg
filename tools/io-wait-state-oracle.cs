// Independent .NET Framework reader for a live I/O collector in the regression.
using System;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Threading;

class IoWaitStateOracle
{
    [DllImport("kernel32.dll")]
    static extern ulong GetTickCount64();

    static int Main(string[] args)
    {
        if (args.Length != 2) return 2;
        int pid = int.Parse(args[0]), tid = int.Parse(args[1]);
        using (Process process = Process.GetProcessById(pid))
        {
            long processBirth = process.StartTime.ToUniversalTime().ToFileTimeUtc();
            for (int i = 0; i < 5; ++i)
            {
                ulong begin = GetTickCount64();
                process.Refresh();
                bool found = false;
                foreach (ProcessThread thread in process.Threads)
                {
                    using (thread)
                    {
                        if (thread.Id != tid) continue;
                        long threadBirth = thread.StartTime.ToUniversalTime().ToFileTimeUtc();
                        System.Diagnostics.ThreadState state = thread.ThreadState;
                        string reason = state == System.Diagnostics.ThreadState.Wait ? thread.WaitReason.ToString() : "None";
                        ulong end = GetTickCount64();
                        const string format = "{{\"schema\":\"kn.io_thread_wait_witness.v1\",\"pid\":{0},\"tid\":{1}," +
                            "\"process_created\":\"{2}\",\"thread_created\":\"{3}\",\"start_tick_ms\":\"{4}\",\"end_tick_ms\":\"{5}\"," +
                            "\"managed_thread_state\":{6},\"managed_wait_reason\":\"{7}\"}}";
                        Console.WriteLine(string.Format(CultureInfo.InvariantCulture, format, pid, tid, processBirth, threadBirth, begin, end, (int)state, reason));
                        found = true;
                    }
                }
                if (!found) return 1;
                if (i < 4) Thread.Sleep(25);
            }
        }
        return 0;
    }
}
