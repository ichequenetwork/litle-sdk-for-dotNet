using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using Tamir.SharpSsh.jsch;

namespace Litle.Sdk
{
    public class Communications
    {
        private static readonly object _synLock = new object();
        private readonly IDictionary<string, StringBuilder> _cache;

        public Communications(IDictionary<string, StringBuilder> cache)
        {
            _cache = cache;
        }

        public static bool ValidateServerCertificate(
            object sender,
            X509Certificate certificate,
            X509Chain chain,
            SslPolicyErrors sslPolicyErrors)
        {
            if (sslPolicyErrors == SslPolicyErrors.None)
                return true;

            Console.WriteLine("Certificate error: {0}", sslPolicyErrors);

            // Do not allow this client to communicate with unauthenticated servers. 
            return false;
        }

        public void neuterXML(ref string inputXml)
        {
            var pattern1 = "(?i)<number>.*?</number>";
            var pattern2 = "(?i)<accNum>.*?</accNum>";

            var rgx1 = new Regex(pattern1);
            var rgx2 = new Regex(pattern2);
            inputXml = rgx1.Replace(inputXml, "<number>xxxxxxxxxxxxxxxx</number>");
            inputXml = rgx2.Replace(inputXml, "<accNum>xxxxxxxxxx</accNum>");
        }

        public void log(string logMessage, string logFile, bool neuter)
        {
            lock (_synLock)
            {
                if (neuter)
                {
                    neuterXML(ref logMessage);
                }
                var logWriter = new StreamWriter(logFile, true);
                var time = DateTime.Now;
                logWriter.WriteLine(time.ToString());
                logWriter.WriteLine(logMessage + "\r\n");
                logWriter.Close();
            }
        }

        public virtual string HttpPost(string xmlRequest, Dictionary<string, string> config)
        {
            string logFile = null;
            if (config.ContainsKey("logFile"))
            {
                logFile = config["logFile"];
            }

            var uri = config["url"];
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls11 |
                                                   SecurityProtocolType.Tls;
            var req = (HttpWebRequest) WebRequest.Create(uri);

            var neuter = false;
            if (config.ContainsKey("neuterAccountNums"))
            {
                neuter = ("true".Equals(config["neuterAccountNums"]));
            }

            var printxml = false;
            if (config.ContainsKey("printxml"))
            {
                if ("true".Equals(config["printxml"]))
                {
                    printxml = true;
                }
            }
            if (printxml)
            {
                Console.WriteLine(xmlRequest);
                Console.WriteLine(logFile);
            }

            //log request
            if (logFile != null)
            {
                log(xmlRequest, logFile, neuter);
            }

            req.ContentType = "text/xml";
            req.Method = "POST";
            req.ServicePoint.MaxIdleTime = 10000;
            req.ServicePoint.Expect100Continue = false;
            if (isProxyOn(config))
            {
                var myproxy = new WebProxy(config["proxyHost"], int.Parse(config["proxyPort"]));
                myproxy.BypassProxyOnLocal = true;
                req.Proxy = myproxy;
            }

            // submit http request
            using (var writer = new StreamWriter(req.GetRequestStream()))
            {
                writer.Write(xmlRequest);
            }


            // read response
            var resp = req.GetResponse();
            if (resp == null)
            {
                return null;
            }
            string xmlResponse;
            using (var reader = new StreamReader(resp.GetResponseStream()))
            {
                xmlResponse = reader.ReadToEnd().Trim();
            }
            if (printxml)
            {
                Console.WriteLine(xmlResponse);
            }

            //log response
            if (logFile != null)
            {
                log(xmlResponse, logFile, neuter);
            }

            return xmlResponse;
        }

        public bool isProxyOn(Dictionary<string, string> config)
        {
            return config.ContainsKey("proxyHost") && config["proxyHost"] != null && config["proxyHost"].Length > 0 &&
                   config.ContainsKey("proxyPort") && config["proxyPort"] != null && config["proxyPort"].Length > 0;
        }

        public struct SshConnectionInfo
        {
            public string Host;
            public string User;
            public string Pass;
            public string IdentityFile;
        }
    }
}
