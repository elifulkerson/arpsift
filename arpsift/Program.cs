using System;
using System.Runtime.InteropServices;
using System.ComponentModel;
using System.Net;
using System.Collections.Generic;
using System.Threading;


// Grabbed the "how to read the windows arp table programmatically" bits from here:
// https://stackoverflow.com/questions/1148778/how-do-i-access-arp-protocol-information-through-net

namespace arpalyze
{

    class Program
    {
        static string MAC_00 = "00-00-00-00-00-00";
        static string DATEFORMAT = "HH:mm:ss.fff";

        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GenerateConsoleCtrlEvent(CtrlTypes dwCtrlEvent, uint dwProcessGroupId);

        [DllImport("Kernel32")]
        public static extern bool SetConsoleCtrlHandler(HandlerRoutine Handler, bool Add);

        public delegate bool HandlerRoutine(CtrlTypes CtrlType);

        static HandlerRoutine consoleHandler;

        static Dictionary<string, string> OUIDB = new Dictionary<string, string>();

        public enum CtrlTypes
        {
            CTRL_C_EVENT = 0,
            CTRL_BREAK_EVENT,
            CTRL_CLOSE_EVENT,
            CTRL_LOGOFF_EVENT = 5,
            CTRL_SHUTDOWN_EVENT
        }

        private static bool CtrlHandler(CtrlTypes ctrlType)
        {

            // Put your own handler here
            switch (ctrlType)
            {
                case CtrlTypes.CTRL_C_EVENT:
                    Console.ResetColor();
                    //Console.WriteLine("ctrl-c");
                    done = true;
                    break;

                case CtrlTypes.CTRL_BREAK_EVENT:
                    Console.ResetColor();
                    //Console.WriteLine("ctrl-break");
                    dumpflag = true;
                    break;
            }

            return true;
        }

        // The max number of physical addresses.
        const int MAXLEN_PHYSADDR = 8;

        // Define the MIB_IPNETROW structure.
        [StructLayout(LayoutKind.Sequential)]
        struct MIB_IPNETROW
        {
            [MarshalAs(UnmanagedType.U4)]
            public int dwIndex;
            [MarshalAs(UnmanagedType.U4)]
            public int dwPhysAddrLen;
            [MarshalAs(UnmanagedType.U1)]
            public byte mac0;
            [MarshalAs(UnmanagedType.U1)]
            public byte mac1;
            [MarshalAs(UnmanagedType.U1)]
            public byte mac2;
            [MarshalAs(UnmanagedType.U1)]
            public byte mac3;
            [MarshalAs(UnmanagedType.U1)]
            public byte mac4;
            [MarshalAs(UnmanagedType.U1)]
            public byte mac5;
            [MarshalAs(UnmanagedType.U1)]
            public byte mac6;
            [MarshalAs(UnmanagedType.U1)]
            public byte mac7;
            [MarshalAs(UnmanagedType.U4)]
            public int dwAddr;
            [MarshalAs(UnmanagedType.U4)]
            public int dwType;
        }

        // Declare the GetIpNetTable function.
        [DllImport("IpHlpApi.dll")]
        [return: MarshalAs(UnmanagedType.U4)]
        static extern int GetIpNetTable(
           IntPtr pIpNetTable,
           [MarshalAs(UnmanagedType.U4)]
         ref int pdwSize,
           bool bOrder);

        [DllImport("IpHlpApi.dll", SetLastError = true, CharSet = CharSet.Auto)]
        internal static extern int FreeMibTable(IntPtr plpNetTable);

        // The insufficient buffer error.
        const int ERROR_INSUFFICIENT_BUFFER = 122;

        static bool dumpflag = false;
        static bool done = false;

        static bool CONFIG_DATE = true;
        static int CONFIG_SLEEPLEN = 1;
        static bool CONFIG_OUI = true;
        static bool CONFIG_SPECIFIED_HEXFILE = false;


        static string[] ARPStatusCodes = new string[] { "code0", "code1", "invalid", "dynamic", "static" };

        private static long ip2long(IPAddress ip) {
            byte[] bytes = ip.GetAddressBytes();

            return (long) ( 16777216 * (long)bytes[0] + 65536 * (long)bytes[1] + 256 * (long)bytes[2] + (long)bytes[3]);
        }

         private static int CompareIPs(IPAddress x, IPAddress y)
        {

             long xl = ip2long(x);
             long yl = ip2long(y);

             if (xl == yl) { return 0;}
             if (xl > yl) {return 1;}
             if (yl > xl) {return -1;}

             return 0;
        }

        static void BlueBar()
         {
             //Console.BackgroundColor = ConsoleColor.DarkBlue;
             Console.Write("-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-");
             //Console.ResetColor();
             Console.WriteLine("");
         }

        static void WriteOUI(string MAC)
        {
            if (CONFIG_OUI)
            {
                if (OUIDB.ContainsKey(MAC.Substring(0,8)))
                {
                    Console.Write(" {0}",OUIDB[MAC.Substring(0,8)]);
                }
            }
        }
       
        static void Main(string[] args)
        {

            string ouifile = "oui.hex.txt";

            for (int i = 0; i < args.Length; i++)
            {
                string arg = args[i];
                if (arg == "-v" || arg == "--version" || arg == "/v" || arg == "/version")
                {
                    Console.WriteLine("arpsift.exe v0.2 by Eli Fulkerson - Mar/2/2016");
                    Console.WriteLine("http://www.elifulkerson.com");
                    return;
                }

                if (arg == "-h" || arg == "--help" || arg == "/h" || arg == "/help" || arg == "?" || arg == "/?" || arg == "-?" )
                {
                    Console.WriteLine("Usage: arpsift [-d] [-w ms] [-o] [-f filename]");
                    Console.WriteLine("");
                    Console.WriteLine("Options:");
                    Console.WriteLine("    -d\tDo not include timestamp on every line");
                    Console.WriteLine("    -w X\tSleep X milliseconds between polls (default 1)");
                    Console.WriteLine("    -o\tDo not include OUI information");
                    Console.WriteLine("    -f X\tSpecify that X is the OUI filename.  (default: oui.hex.txt)");

                    Console.WriteLine("");
                    Console.WriteLine("The OUI file may be acquired from http://standards-oui.ieee.org/oui.txt");
                    Console.WriteLine("Also: http://standards.ieee.org/develop/regauth/iab/iab.txt");
                    Console.WriteLine("This tool only uses the (hex) lines.  For the sake of file size, you can");
                    Console.WriteLine("remove all other lines in the file.");

                    Console.WriteLine("");
                    Console.WriteLine("arpsift.exe v0.2 by Eli Fulkerson - Mar/2/2016");
                    Console.WriteLine("http://www.elifulkerson.com");
                    return;
                }

                if (arg == "-d" )
                {
                    CONFIG_DATE = false;
                }

                if (arg == "-w")
                {
                    try
                    {
                        CONFIG_SLEEPLEN = Convert.ToInt32(args[i + 1]);
                    }
                    catch
                    {
                        CONFIG_SLEEPLEN = 1;
                    }
                }

                if (arg == "-f" || arg == "--file")
                {
                    try { ouifile = args[i + 1]; CONFIG_SPECIFIED_HEXFILE = true; }
                    catch { ouifile = "oui.hex.txt"; }
                }

                if (arg == "-o" || arg == "--oui" || arg == "/o" || arg == "/oui")
                {
                    CONFIG_OUI = false;
                }

            }

            // read in our ouis
            

            try
            {
                // slightly funky because if we specified a path we don't want to conflate it with the location of the exe
                System.IO.StreamReader ouis;

                if (!CONFIG_SPECIFIED_HEXFILE) {
                    ouis = new System.IO.StreamReader(System.IO.Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location) + @"\" + ouifile);
                }
                else
                {
                    ouis = new System.IO.StreamReader(ouifile);
                }

                string line;
                while ((line = ouis.ReadLine()) != null)
                {
                    // We are assuming they never change the oui.hex.txt file structure
                    if (line.Contains("(hex)\t"))
                    {
                        string[] ouisplit = line.Split(new char[] { '\t' }, StringSplitOptions.RemoveEmptyEntries);
                        OUIDB[ouisplit[0].Substring(0, 8)] = ouisplit[1];
                    }
                }
                ouis.Close();

                Console.WriteLine("FYI: {0} OUIs read from {1}", OUIDB.Count, ouifile);
            }
            catch( System.IO.FileNotFoundException e) {
                Console.WriteLine("FYI: Cannot open file: {0} - OUI lookup not available", ouifile);
            }

            DateTime StartUpTime = DateTime.Now;
    
            // Probably should be a single data type but I really don't feel like screwing with it right now.
            // Also, I'm cheating because they keys are synced and using one dictionary.keys to iterate through other dictionaries so they
            // stay modifiable...
            Dictionary<IPAddress, bool> DictPresent = new Dictionary<IPAddress, bool>();
            Dictionary<IPAddress, string> DictMAC = new Dictionary<IPAddress, string>();
            Dictionary<IPAddress, DateTime> DictFirstSeen = new Dictionary<IPAddress, DateTime>();
            Dictionary<IPAddress, int> DictTypes = new Dictionary<IPAddress, int>();

            long numAdds = 0;
            long numDeletes = 0;
            long numInvalidates = 0;
            long numValidates = 0;
            long numChanges = 0;

            consoleHandler = new HandlerRoutine(CtrlHandler);
            SetConsoleCtrlHandler(consoleHandler, true);

            BlueBar();
            Console.WriteLine("Analyzing ARP Activity:");
            Console.WriteLine("-- Timestamps are local to this tool, they are not read from the OS.");
            Console.WriteLine("-- This tool analyzes the ARP table, it does not sniff traffic.");
            Console.WriteLine("-- ctrl-break to show ARP table, ctrl-c to exit ");
            BlueBar();

            done = false;

            while (!done)
            {
                // The number of bytes needed.
                int bytesNeeded = 0;

                // The result from the API call.
                int result = GetIpNetTable(IntPtr.Zero, ref bytesNeeded, false);

                // Call the function, expecting an insufficient buffer.
                if (result != ERROR_INSUFFICIENT_BUFFER)
                {
                    // Throw an exception.
                    throw new Win32Exception(result);
                }

                // Allocate the memory, do it in a try/finally block, to ensure
                // that it is released.
                IntPtr buffer = IntPtr.Zero;

                // Try/finally.
                try
                {
                    // Allocate the memory.
                    buffer = Marshal.AllocCoTaskMem(bytesNeeded);

                    // Make the call again. If it did not succeed, then
                    // raise an error.
                    result = GetIpNetTable(buffer, ref bytesNeeded, false);

                    // If the result is not 0 (no error), then throw an exception.
                    if (result != 0)
                    {
                        // Throw an exception.
                        throw new Win32Exception(result);
                    }

                    // Now we have the buffer, we have to marshal it. We can read
                    // the first 4 bytes to get the length of the buffer.
                    int entries = Marshal.ReadInt32(buffer);

                    // Increment the memory pointer by the size of the int.
                    IntPtr currentBuffer = new IntPtr(buffer.ToInt64() +
                        Marshal.SizeOf(typeof(int)));

                    // Allocate an array of entries.
                    MIB_IPNETROW[] table = new MIB_IPNETROW[entries];

                    // Cycle through the entries.
                    for (int index = 0; index < entries; index++)
                    {
                        // Call PtrToStructure, getting the structure information.
                        table[index] = (MIB_IPNETROW)Marshal.PtrToStructure(new
                            IntPtr(currentBuffer.ToInt64() + (index *
                            Marshal.SizeOf(typeof(MIB_IPNETROW)))), typeof(MIB_IPNETROW));
                    }


                    Dictionary<IPAddress, string> DictNewInfoMAC = new Dictionary<IPAddress, string>();
                    Dictionary<IPAddress, int> DictNewInfoTypes = new Dictionary<IPAddress, int>();

                    for (int index = 0; index < entries; index++)
                    {
                        MIB_IPNETROW row = table[index];
                        IPAddress ip = new IPAddress(BitConverter.GetBytes(row.dwAddr));
                            
                        string macstring = row.mac0.ToString("X2") + '-' + row.mac1.ToString("X2") + '-' + row.mac2.ToString("X2") + '-' + row.mac3.ToString("X2") + '-' + row.mac4.ToString("X2") + '-' + row.mac5.ToString("X2");  //@@ fix this {} 

                        // if we don't already have this one - or if we do but its a redundant IP and the other one had a bullshit MAC, just overwrite it.
                        // if we don't do uniques here we end up deleting/adding anew all the multicast addresses every single cycle - they are in the list twice, once as MAC_00 and
                        // a second time with a valid MAC
                        if ( !DictNewInfoMAC.ContainsKey(ip) || DictNewInfoMAC[ip] == "00-00-00-00-00-00")
                        {
                            DictNewInfoMAC[ip] = macstring;
                            DictNewInfoTypes[ip] = row.dwType;
                        }
                    }

                    // at this point, we have all of our new data in the DictSource structures.

                    // first, set present to false so we can see who is missing
                    foreach (IPAddress k in DictMAC.Keys)  // cleveryly using DictMAC's keys to update DictPresent
                    {
                        DictPresent[k] = false;
                    }

                        
                    foreach (IPAddress ip in DictNewInfoMAC.Keys)
                    {
                        if (DictPresent.ContainsKey(ip))
                        {
                            // We already have this ip address in our list, lets update its status
                            DictPresent[ip] = true;
                                
                            // BRIGHT RED valid->valid change.  This is the condition we are trying to check
                            if (DictMAC[ip] != DictNewInfoMAC[ip] && DictNewInfoMAC[ip] != MAC_00 && DictMAC[ip] != MAC_00)
                            {
                                Console.BackgroundColor = ConsoleColor.Red;
                                Console.ForegroundColor = ConsoleColor.White;
                                Console.Write("! {0,-15} changed to {1}  (was {2} for {3:F3} s)", ip.ToString(), DictNewInfoMAC[ip], DictMAC[ip], (DateTime.Now - DictFirstSeen[ip]).TotalSeconds);
                                if (CONFIG_DATE) { Console.Write(" {0}", DateTime.Now.ToString(DATEFORMAT)); }
                                WriteOUI(DictNewInfoMAC[ip]);
                                Console.ResetColor();
                                Console.WriteLine();

                                numChanges++;
                            }
                            // valid -> invalid
                            if (DictMAC[ip] != DictNewInfoMAC[ip] && DictMAC[ip] == MAC_00)
                            {
                                //Console.BackgroundColor = ConsoleColor.DarkGreen;
                                //Console.ForegroundColor = ConsoleColor.Gray;
                                Console.Write("+ {0,-15} is at {1}  (was invalid ({2}) for {3:F3} s)", ip.ToString(), DictNewInfoMAC[ip], DictMAC[ip], (DateTime.Now - DictFirstSeen[ip]).TotalSeconds);
                                //Console.ResetColor();
                                if (CONFIG_DATE) { Console.Write(" {0}", DateTime.Now.ToString(DATEFORMAT)); }
                                WriteOUI(DictNewInfoMAC[ip]);
                                Console.WriteLine();

                                numValidates++;
                            }
                            // valid -> invalid
                            if (DictMAC[ip] != DictNewInfoMAC[ip] && DictNewInfoMAC[ip] == MAC_00)
                            {
                                Console.BackgroundColor = ConsoleColor.DarkYellow;
                                Console.ForegroundColor = ConsoleColor.White;
                                Console.Write("- {0,-15} invalidated (was {1} for {2:F3} s)", ip.ToString(), DictMAC[ip], (DateTime.Now - DictFirstSeen[ip]).TotalSeconds);
                                if (CONFIG_DATE) { Console.Write(" {0}", DateTime.Now.ToString(DATEFORMAT)); }
                                
                                Console.ResetColor();
                                Console.WriteLine();

                                numInvalidates++;
                            }

                            // finally, if they aren't the same for any reason, we update the data.
                            if (DictMAC[ip] != DictNewInfoMAC[ip])
                            {
                                DictTypes[ip] = DictNewInfoTypes[ip];
                                DictMAC[ip] = DictNewInfoMAC[ip];
                                DictFirstSeen[ip] = DateTime.Now;
                                DictPresent[ip] = true;
                            }

                        } else
                        {
                            // We don't already have this ip address in our list, lets add it!           
                            Console.Write("+ {0,-15} is at {1}", ip.ToString(), DictNewInfoMAC[ip]);
                            if (CONFIG_DATE) { Console.Write(" {0}", DateTime.Now.ToString(DATEFORMAT)); }
                            WriteOUI(DictNewInfoMAC[ip]);
                            Console.WriteLine("");

                            DictTypes[ip] = DictNewInfoTypes[ip];
                            DictMAC[ip] = DictNewInfoMAC[ip];
                            DictFirstSeen[ip] = DateTime.Now;
                            DictPresent[ip] = true;

                            numAdds++;
                        }
                    } 

                    // goners
                    List<IPAddress> removals = new List<IPAddress>();
                    foreach (IPAddress k in DictPresent.Keys)
                    {
                        // if key wasn't present in the last cycle - add them to the delete list
                        if (DictPresent[k] == false)
                        {
                            Console.BackgroundColor = ConsoleColor.DarkRed;
                            Console.ForegroundColor = ConsoleColor.Gray;

                            Console.Write("- {0,-15} deleted (was {1} for {2:F3}s)", k.ToString(), DictMAC[k], (DateTime.Now - DictFirstSeen[k]).TotalSeconds);
                            if (CONFIG_DATE) { Console.Write(" {0}", DateTime.Now.ToString(DATEFORMAT)); }
                            WriteOUI(DictMAC[k]);
                            Console.ResetColor();
                            Console.WriteLine();

                            removals.Add(k);
                        }
                    }

                    //kill everything on the delete list
                    foreach (IPAddress k in removals)
                    {
                        DictTypes.Remove(k);
                        DictPresent.Remove(k);
                        DictMAC.Remove(k);
                        DictFirstSeen.Remove(k);
                        numDeletes++;
                    }

                    // dumpflag is set by control-break.  if hit, display one screen of data and turn the flag off.
                    if (dumpflag)
                    {

                        BlueBar();
                        Console.WriteLine("ARP Table:");
                        //Console.WriteLine("*** DEBUG: sizeof Present {0} MAC {1} FirstSeen{2} ***", DictPresent.Count, DictMAC.Count, DictFirstSeen.Count);
                        Console.Write("  {0,-20}{1,-20}{2,8}{3,10}", "Internet Address", "Physical Address", "Type", "Idle(s)");
                        if (CONFIG_DATE) { Console.Write("  {0,-12} ", "Time"); }
                        if (CONFIG_OUI) { Console.Write(" {0}", "OUI"); }
                        Console.WriteLine("");

                        IPAddress[] keylist = new List<IPAddress>(DictMAC.Keys).ToArray();
                        Array.Sort(keylist, CompareIPs);
                            
                        //foreach (IPAddress k in DictPresent.Keys)
                        foreach (IPAddress k in keylist)
                        {
                            Console.Write("  {0,-20}{1,-20}{2,8}{3,10:F3}", k, DictMAC[k], ARPStatusCodes[DictTypes[k]], (DateTime.Now - DictFirstSeen[k]).TotalSeconds);
                            if (CONFIG_DATE) { Console.Write("  {0,-12} ", DictFirstSeen[k].ToString(DATEFORMAT)); }
                            WriteOUI(DictMAC[k]);
                            Console.WriteLine("");
                        }
                        Console.WriteLine("Statistics:");
                        Console.WriteLine("  Running for: {0:F3} seconds, started at {1}", (DateTime.Now - StartUpTime).TotalSeconds, StartUpTime.ToString("o"));
                        Console.WriteLine("  Activity:  adds:{0}  deletes:{1}  changes:{2}  invalidates:{3}  un-invalidates:{4}", numAdds, numDeletes, numChanges, numInvalidates, numValidates);
                        BlueBar();
                        dumpflag = false;
                    }
              
                }
                finally
                {
                    // Release the memory.
                    FreeMibTable(buffer);
                }

                // Lets not eat up the whole CPU...
                // @@ consider making this customizable
                System.Threading.Thread.Sleep(CONFIG_SLEEPLEN);
            }
        }     
    }
}