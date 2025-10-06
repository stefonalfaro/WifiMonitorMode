using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SharpPcap;

class WifiScanner
{
    // Simple AP & Station stores
    static ConcurrentDictionary<string, (string ssid, int channel)> APs = new();
    static ConcurrentDictionary<string, string> StationToBssid = new();

    static void Main()
    {
        var devices = CaptureDeviceList.Instance;
        if (devices.Count < 1){
            Console.WriteLine("No devices found.");
            return;
        }

        Console.WriteLine("Available capture devices:");
        for (int i = 0; i < devices.Count; i++){
            Console.WriteLine($"{i}: {devices[i].Description ?? devices[i].Name}");
        }

        Console.Write("Select the device number: ");
        int index = int.Parse(Console.ReadLine());
        var dev = devices[index];
        Console.WriteLine("Using device: " + (dev.Description ?? dev.Name));
        Console.WriteLine("Make sure this interface is in monitor mode (iw dev ... set monitor).");

        // Optional: set BPF filter to reduce noise (capture management + data)
        string bpf = "type mgt or type data"; // captures management and data frames

        // Configure the device
        var config = new DeviceConfiguration{
            ReadTimeout = 1000 // read timeout in milliseconds
        };

        // Open the device
        dev.Open(config);

        try { dev.Filter = bpf; } catch { /* not all platforms allow setting filter the same way */ }

        dev.OnPacketArrival += (sender, e) =>
        {
            byte[] raw = e.Data.ToArray();     

            if (raw.Length < 4) return;

            // Parse radiotap length (offsets 2..3 little-endian)
            if (raw.Length < 4) return;
            int rtLen = BitConverter.ToUInt16(raw, 2);
            if (raw.Length <= rtLen + 10) return; // need header + addresses

            int hdr = rtLen; // 802.11 header starts here

            byte frameControl0 = raw[hdr + 0];
            byte frameControl1 = raw[hdr + 1];
            int type = (frameControl0 >> 2) & 0x3;
            int subtype = (frameControl0 >> 4) & 0xF;
            bool toDS = (frameControl1 & 0x01) != 0;
            bool fromDS = (frameControl1 & 0x02) != 0;

            // Addresses: addr1, addr2, addr3 (6 bytes each) start at offset hdr+4
            string addr1 = MacToString(raw, hdr + 4);
            string addr2 = MacToString(raw, hdr + 10);
            string addr3 = MacToString(raw, hdr + 16);

            // Management frames (type == 0)
            if (type == 0)
            {
                // Association Request subtype = 0x0, Association Response = 0x1
                if (subtype == 0x0) // Association Request
                {
                    // addr2 = STA (source), addr1 = AP (destination; usually ff:ff:... for broadcast?), addr3 = BSSID
                    Console.WriteLine($"[ASSOC-REQ] {addr2} -> {addr1} (bssid {addr3})");
                    StationToBssid[addr2] = addr3;
                }
                else if (subtype == 0x1) // Assoc Response
                {
                    Console.WriteLine($"[ASSOC-RESP] {addr2} -> {addr1} (bssid {addr3})");
                    // Could inspect response to confirm success (status code in payload)
                }
                else if (subtype == 0x8) // Beacon
                {
                    // Parse tags to extract SSID and channel
                    int mgmtHeaderLen = 24; // management header is 24 bytes (addr fields included)
                    int pos = hdr + mgmtHeaderLen;
                    if (pos + 12 <= raw.Length) // need fixed fields (timestamp 8, interval 2, cap 2)
                    {
                        pos += 12; // move to the tagged parameters
                        string ssid = "<hidden>";
                        int channel = -1;
                        while (pos + 2 <= raw.Length)
                        {
                            byte elementId = raw[pos];
                            byte length = raw[pos + 1];
                            if (pos + 2 + length > raw.Length) break;
                            if (elementId == 0) // SSID
                            {
                                var bytes = new byte[length];
                                Array.Copy(raw, pos + 2, bytes, 0, length);
                                ssid = Encoding.UTF8.GetString(bytes);
                            }
                            else if (elementId == 3) // DS Parameter set: current channel
                            {
                                channel = raw[pos + 2];
                            }
                            // 48 = RSN IE (encryption) could be parsed for WPA/WPA2 info
                            pos += 2 + length;
                        }

                        // addr3 is BSSID for beacon frames
                        APs.AddOrUpdate(addr3, (ssid, channel), (k, v) => (ssid.Length > 0 ? ssid : v.ssid, channel > 0 ? channel : v.channel));
                        Console.WriteLine($"[BEACON] BSSID={addr3} SSID=\"{ssid}\" CH={channel}");
                    }
                }
                else if (subtype == 0x4) // Probe Request (clients probing)
                {
                    // addr2 = STA
                    Console.WriteLine($"[PROBE-REQ] {addr2}");
                }
            }
            // Data frames (type == 2) — used to infer active associations as well
            else if (type == 2)
            {
                // Determine BSSID based on ToDS/FromDS per 802.11:
                // - ToDS=0, FromDS=0: addr3 is BSSID (ad-hoc / AP = addr3)
                // - ToDS=1, FromDS=0: addr3 is dest? (when from STA to AP addr2=STA, addr1=AP)
                // For simplicity: if any address matches a known BSSID, map the other as the STA
                string bssidCandidate = null;
                if (APs.ContainsKey(addr1)) bssidCandidate = addr1;
                else if (APs.ContainsKey(addr2)) bssidCandidate = addr2;
                else if (APs.ContainsKey(addr3)) bssidCandidate = addr3;

                if (bssidCandidate != null)
                {
                    // The station is whichever address is not the BSSID and not the broadcast/multicast addr
                    string sta = (addr1 != bssidCandidate && !IsMulticast(addr1)) ? addr1 :
                                 (addr2 != bssidCandidate && !IsMulticast(addr2)) ? addr2 :
                                 (addr3 != bssidCandidate && !IsMulticast(addr3)) ? addr3 : null;
                    if (sta != null)
                    {
                        StationToBssid[sta] = bssidCandidate;
                        Console.WriteLine($"[DATA] {sta} <-> {bssidCandidate}");
                    }
                }
            }

            // Periodically print summary
            if (DateTime.Now.Second % 10 == 0)
            {
                PrintSummary();
            }
        };

        dev.StartCapture();
        Console.WriteLine("Capturing... press Ctrl+C to exit.");
        Console.CancelKeyPress += (s, a) =>
        {
            dev.StopCapture();
            dev.Close();
            PrintSummary(final:true);
            Environment.Exit(0);
        };

        // keep process alive
        while (true) System.Threading.Thread.Sleep(1000);
    }

    static string MacToString(byte[] b, int offset)
    {
        if (offset + 6 > b.Length) return "00:00:00:00:00:00";
        return string.Join(":", Enumerable.Range(0, 6).Select(i => b[offset + i].ToString("x2")));
    }

    static bool IsMulticast(string mac)
    {
        // simplest test: low bit of first octet
        var first = Convert.ToByte(mac.Split(':')[0], 16);
        return (first & 0x01) == 1;
    }

    static void PrintSummary(bool final=false)
    {
        Console.WriteLine(final ? "\n=== Final Summary ===" : "\n=== Live Summary ===");
        Console.WriteLine("APs:");
        foreach (var kv in APs)
        {
            Console.WriteLine($" - {kv.Key}  SSID=\"{kv.Value.ssid}\" CH={kv.Value.channel}");
        }
        Console.WriteLine("Stations:");
        foreach (var kv in StationToBssid)
        {
            Console.WriteLine($" - {kv.Key} -> {kv.Value}");
        }
    }
}
