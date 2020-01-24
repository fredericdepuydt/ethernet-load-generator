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
using Application;


namespace Application
{
    class SendingASinglePacketWithSendPacket
    {
        static void SendPackets()
        {
            // Retrieve the device list from the local machine
            IList<LivePacketDevice> allDevices = LivePacketDevice.AllLocalMachine;

            if (allDevices.Count == 0)
            {
                Console.WriteLine("No interfaces found! Make sure WinPcap is installed.");
                return;
            }

            // Print the list
            for (int i = 0; i != allDevices.Count; ++i)
            {
                LivePacketDevice device = allDevices[i];
                Console.Write((i + 1) + ". " + device.Name);
                if (device.Description != null)
                    Console.WriteLine(" (" + device.Description + ")");
                else
                    Console.WriteLine(" (No description available)");
            }

            int deviceIndex = 0;
            do
            {
                Console.WriteLine("Enter the interface number (1-" + allDevices.Count + "):");
                string deviceIndexString = Console.ReadLine();
                if (!int.TryParse(deviceIndexString, out deviceIndex) ||
                    deviceIndex < 1 || deviceIndex > allDevices.Count)
                {
                    deviceIndex = 0;
                }
            } while (deviceIndex == 0);
            
            PacketDevice selectedDevice = allDevices[deviceIndex - 1];
            using (PacketCommunicator communicator = selectedDevice.Open(1, // name of the device
                                                                         PacketDeviceOpenAttributes.MaximumResponsiveness, // promiscuous mode
                                                                         1000)) // read timeout
            {

                Packet pack = BuildPackets.BuildVLanTaggedFramePacket();
                PacketSendBuffer packbuffer = new PacketSendBuffer(1526000);
                for (int i = 0; i != 1000; ++i)
                {
                    packbuffer.Enqueue(pack);
                }

                for (int i = 0; i != 1000; ++i)
                {
                    communicator.Transmit(packbuffer, false);
                }
            }
        }
    }
}