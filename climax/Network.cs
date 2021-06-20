using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net;

namespace climax
{
    class Network
    {
        public dynamic Request<T>(object type, string url)
        {
            var network = new WebClient();
            WebRequest.DefaultWebProxy = null;

            network.Headers.Add("User-Agent", "");
            switch (type)
            {
                case byte[] _:
                    return network.DownloadData(url);
                case string _:
                    return network.DownloadString(url);
                default:
                    return null;
            }
        }

    }
}
