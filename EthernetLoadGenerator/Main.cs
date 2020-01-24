using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using PcapDotNet.Base;
using PcapDotNet.Core;
using PcapDotNet.Packets;
using PcapDotNet.Packets.Arp;
using PcapDotNet.Packets.Dns;
using PcapDotNet.Packets.Ethernet;
using PcapDotNet.Packets.Gre;
using PcapDotNet.Packets.Http;
using PcapDotNet.Packets.Icmp;
using PcapDotNet.Packets.Igmp;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Packets.IpV6;
using PcapDotNet.Packets.Transport;


namespace Application
{
    class MainClass
    {
        
        public static void Main(string[] args)
        {
            //Packet P1,P2,P3,P4,P5,P6,P7;*/

            ProcentualLoad.SetupInterface();
            /*
            
            P1 = BuildPackets.BuildArpPacket();
            P2 = BuildPackets.BuildProfinetFramePacket();
            P3 = BuildPackets.BuildUdpPacket();
            P4 = BuildPackets.BuildIpV4Packet();
            P5 = BuildPackets.BuildIpV4Packet();
            P6 = BuildPackets.BuildIpV4Packet();
            P7 = BuildPackets.BuildIcmpPacket();

            while (true)
            {
                ProcentualLoad.Communicator.SendPacket(P1);
                
                ProcentualLoad.Communicator.SendPacket(P2);

                ProcentualLoad.Communicator.SendPacket(P3);

                ProcentualLoad.Communicator.SendPacket(P4);
                                
                ProcentualLoad.Communicator.SendPacket(P5);
                                
                ProcentualLoad.Communicator.SendPacket(P6);
                                
                ProcentualLoad.Communicator.SendPacket(P7);
            }
            */
            
            int load = 0;
            do
            {
                Console.WriteLine("Enter the load percentage: ");
                string loadString = Console.ReadLine();
                if (!int.TryParse(loadString, out load) ||
                    load < 1 || load > 100)
                {
                    Console.WriteLine("Wrong load (must be between 1-100)");
                    load = 0;
                }
            } while (load == 0);

            ProcentualLoad.ApplyLoad(load);

            //CapturingThePacketsWithoutTheCallback.HandlePackets();

        }
    }
};
